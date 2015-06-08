/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of MinerPP.
 *
 * MinerPP is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <cassert>

#include <miner/hash.hpp>
#include <miner/logger.hpp>
#include <miner/serial.hpp>
#include <miner/serial_handler.hpp>
#include <miner/serial_port.hpp>
#include <miner/stratum_work.hpp>
#include <miner/utility.hpp>
#include <miner/whirlpool.hpp>

using namespace miner;

serial_handler::serial_handler(std::shared_ptr<serial_port> & owner)
    : serial_port_(owner)
    , strand_(owner->io_service())
	, nonce_start_(0)
{
    // ...
}

void serial_handler::on_read(const char * buf, const std::size_t & len)
{
    assert(0);
}

void serial_handler::set_has_new_work(const bool & val)
{
    if (auto i = serial_port_.lock())
    {
        assert(sizeof(endian_data_) == 128);

        /**
         * Prepare the work.
         */
        if (prepare_work(endian_data_))
        {
#define USE_TEST_WORK 0
#define USE_WORK_MIDSTATE 1

#if (defined USE_TEST_WORK && USE_TEST_WORK)

#if (defined USE_WORK_MIDSTATE && USE_WORK_MIDSTATE)
			/**
			 * Send test work (midstate).
			 */
			send_test_work_midstate64();
#else
			/**
			 * Send test work.
			 */
			send_test_work();
#endif // USE_WORK_MIDSTATE
#else

#if (defined USE_WORK_MIDSTATE && USE_WORK_MIDSTATE)
			send_work_midstate64();
#else
			/**
			 * The work length.
			 */
			enum { work_length = 80 };

			/**
			 * Send 80 bytes of endian_data_.
			 */
            serial::message_t msg;
            
            msg.type = serial::message_type_new_work;
            msg.length = work_length;
			
            std::vector<std::uint8_t> buffer(2 + work_length);
				
            buffer[0] = msg.type;
            buffer[1] = msg.length;

			std::memcpy(&buffer[2], endian_data_, work_length);

			/**
			 * Print the work for debugging.
			 */

			auto index = 0;

			printf("work: ");

			for (auto & i : buffer)
			{
				if (index > 1)
				{
					printf("%d", (unsigned)i);
				}

				if (index++ == 81)
				{
					break;
				}
			}

			printf("\n");

            i->write(
                reinterpret_cast<const char *> (&buffer[0]), buffer.size()
            );
#endif // USE_WORK_MIDSTATE
#endif // USE_TEST_WORK
        }
    }
}

void serial_handler::set_needs_work_restart(const bool & val)
{
    if (auto i = serial_port_.lock())
    {
        serial::message_t msg;
        
        msg.type = serial::message_type_restart;
        msg.length = 0;
        
        std::vector<std::uint8_t> buffer(2);
        
        buffer[0] = msg.type;
        buffer[1] = msg.length;

        i->write(
            reinterpret_cast<const char *> (&buffer[0]), buffer.size()
        );
	}
}

bool serial_handler::prepare_work(std::uint32_t * val)
{
    if (auto i = serial_port_.lock())
    {
        /**
         * Get (a copy of) the work.
         */
        stratum_work_ = i->work();
        
		/**
		 * Generate the work.
		 */
		if (stratum_work_ && stratum_work_->generate())
		{
			/**
			 * Prepare the work.
			 */
			if (stratum_work_->data().size() > 0)
			{
				auto ptr_data = &stratum_work_->data()[0];

				for (auto kk = 0; kk < 32; kk++)
				{
					utility::be32enc(&val[kk], ((std::uint32_t *)ptr_data)[kk]);
				}
                
				utility::be32enc(&val[19], ptr_data[19]);
            
				nonce_start_ = val[19];

				log_debug(
					"Serial handler prepared nonce = " << nonce_start_ << "."
				);

				return true;
			}
		}
    }

    return false;
}

bool serial_handler::handle_result(const serial::message_t & msg)
{
    if (auto i = serial_port_.lock())
    {
		if (stratum_work_)
		{
            /**
             * Allocate the nonce.
             */
            std::uint32_t nonce;

            /**
             * Copy the big-endian nonce from the result.
             */
            std::memcpy(&nonce, &msg.value[0], sizeof(std::uint32_t));
            
            log_debug("got nonce = " << nonce);

            /**
             * Set the nonce in the endian_data_.
             */
            endian_data_[19] = nonce;
            
            /**
             * Decode the nonce from big-endian.
             */
            nonce = utility::be32dec(&nonce);
            
            log_debug("got nonce = " << nonce);

            /**
             * Set the little-endian representation of the nonce in the work.
             */
            stratum_work_->data()[19] = nonce;
            
            /**
             * Allocate the digest buffer.
             */
            std::uint32_t hash64[16];
            
            /**
             * Hash the work.
             */
            hash::final(
                configuration::instance().proof_of_work_type(),
                reinterpret_cast<std::uint8_t *> (&endian_data_[0]), 80,
                reinterpret_cast<std::uint8_t *> (&hash64[0])
            );
            
            /**
             * Perform a pre-check on the hashes bits.
             */
            if ((hash64[7] & 0xFFFFFF00) == 0)
            {
				log_debug("passed pre-check.");
                
				assert(stratum_work_->data()[19] == nonce);

                return hash::check(hash64, stratum_work_->target());
            }
        }
        else
        {
			// ...
        }
    }
    
    return false;
}

void serial_handler::send_test_work()
{
    if (auto i = serial_port_.lock())
    {
		/**
		 * The work length.
		 */
		enum { work_length = 80 };

        serial::message_t msg;
        
        msg.type = serial::message_type_test_work;
        msg.length = work_length;
            
        std::vector<std::uint8_t> buffer(2 + work_length, 0);
            
        buffer[0] = msg.type;
        buffer[1] = msg.length;

		/**
		 * Test primes.
		 */
		buffer[7] = 7;
		buffer[11] = 11;
		buffer[13] = 13;
		buffer[17] = 17;
		buffer[19] = 19;
		buffer[23] = 23;
		buffer[29] = 29;
		buffer[31] = 31;
		buffer[37] = 37;
		buffer[41] = 41;
		buffer[43] = 43;
		buffer[47] = 47;
		buffer[53] = 53;
		buffer[59] = 59;
		buffer[61] = 61;
		buffer[67] = 67;
		buffer[71] = 71;
		buffer[73] = 73;
		buffer[79] = 79;

		nonce_start_ = *reinterpret_cast<std::uint32_t *> (&buffer[2 + 76]);

		log_debug(
			"Serial handler prepared (test) nonce = " << nonce_start_ << "."
		);

        i->write(
            reinterpret_cast<const char *> (&buffer[0]), buffer.size()
        );
	}
}

void serial_handler::send_work_midstate64()
{
    if (auto i = serial_port_.lock())
    {
		/**
         * 64 bytes midstate (big-endian)
         * 20 (last) bytes of the work (big-endian)
         * 32-bit target (big-endian)
		 * 32-bit nonce_end (little-endian)
         */
        
		/**
		 * The work length.
		 */
		enum { work_length = 88 };
        
        serial::message_t msg;
        
        msg.type = serial::message_type_new_work;
        msg.length = work_length;
            
        std::vector<std::uint8_t> buffer(2, 0);
            
        buffer[0] = msg.type;
        buffer[1] = msg.length;

        /**
         * Allocate the midstate.
         */
        std::uint64_t midstate[8];

        /**
         * Calculate midstate.
         */
        whirlpool_midstate(
            reinterpret_cast<const std::uint8_t *>(endian_data_), midstate
        );

        log_debug(
            "Serial handler calculated midstate = " <<
            utility::to_hex(reinterpret_cast<std::uint8_t *> (&midstate[0]),
            reinterpret_cast<std::uint8_t *> (&midstate[0]) + sizeof(midstate))
        );

        /**
         * Append the midstate to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&midstate[0]),
			reinterpret_cast<std::uint8_t *> (&midstate[0]) + sizeof(midstate)
        );

        /**
         * Append the work to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&endian_data_[0]) + 64,
			reinterpret_cast<std::uint8_t *> (&endian_data_[0]) + 80
        );

        /**
         * The target.
         */
        std::uint32_t target = stratum_work_->target()[6];

		utility::be32enc(&target, target);

		log_debug("Serial handler prepared target = " << target << ".");

        /**
         * Append the target to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&target),
			reinterpret_cast<std::uint8_t *> (&target) + sizeof(target)
        );

		/**
		 * The end nonce.
		 */
		std::uint32_t nonce_end = std::numeric_limits<std::uint32_t>::max();
        
        log_debug("Serial handler prepared nonce end = " << nonce_end << ".");
        
        /**
         * Append the nonce_end to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&nonce_end),
			reinterpret_cast<std::uint8_t *> (&nonce_end) + sizeof(nonce_end)
        );

		nonce_start_ = endian_data_[19];

		log_debug(
			"Serial handler prepared (mid-state), size = " << buffer.size()  <<
			", nonce = " << nonce_start_ << "."
		);

		assert(buffer.size() == 2 + work_length);

        i->write(
            reinterpret_cast<const char *> (&buffer[0]), buffer.size()
        );
	}
}

void serial_handler::send_test_work_midstate64()
{
    if (auto i = serial_port_.lock())
    {
		/**
		 * The work length.
		 */
		enum { work_length = 88 };
        
        serial::message_t msg;
        
        msg.type = serial::message_type_test_work;
        msg.length = work_length;
            
        std::vector<std::uint8_t> buffer(2, 0);
            
        buffer[0] = msg.type;
        buffer[1] = msg.length;
        
		/**
		 * Test work (genesis block).
         * 64 bytes midstate (big-endian)
         * 16 (last) bytes of the work (big-endian)
         * 32-bit target (little-endian)
		 * 32-bit nonce_end (little-endian)
         *
         * std::uint32_t version;
         * std::uint8_t hash_previous_block[32];
         * std::uint8_t hash_merkle_root[32];
         * std::uint32_t timestamp;
         * std::uint32_t bits;
         * std::uint32_t nonce;
         *
         * version: 1
         * hash: 15e96604fbcf7cd7e93d072a06f07ccfe1f8fd0099270a075c761c447403a783
         * time: 1419310800
         * nonce: 1419300800
         * bits: 1e0fffff
         */
        auto block_header = utility::from_hex(
            "0100000000000000000000000000000000000000000000000000000000000"
            "00000000000682e0e40ac3516cb44839d92f2381d7267aff0b0faac4cb1cc"
            "ffcbcffd22dce6d0f69854ffff0f1ec0cf9854"
        );
        
        assert(block_header.size() == 80);

        /**
         * Check genesis hash.
         */
        std::vector<std::uint8_t> digest(64, 0);
        
        /**
         * Hash the genesis block header.
         */
        hash::final(
            configuration::proof_of_work_type_whirlpool_xor,
            &block_header[0], block_header.size(), &digest[0]
        );
        
        std::reverse(&digest[0], &digest[32]);

        /**
         * Get the hexidecimal representation of the digest.
         */
        auto hash = utility::to_hex(&digest[0], &digest[32]);
        
        /**
         * Validate the hash matches the genesis block hash.
         */
        assert(
            hash ==
            "15e96604fbcf7cd7e93d072a06f07ccfe1f8fd0099270a075c761c447403a783"
        );
        
        /**
         * Prepare the work.
         */
        auto ptr_data = reinterpret_cast<std::uint32_t *> (&block_header[0]);

        /**
         * The big endian data.
         */
        std::uint32_t endian_data[32];
        
		std::memcpy(endian_data, &block_header[0], 80);

        for (auto kk = 0; kk < 32; kk++)
        {
            utility::be32enc(&endian_data[kk], ((std::uint32_t *)ptr_data)[kk]);
        }

        utility::be32enc(&endian_data[19], ptr_data[19]);

        /**
         * Allocate the midstate.
         */
        std::uint64_t midstate[8];

        /**
         * Calculate midstate.
         */
        whirlpool_midstate(
            reinterpret_cast<const std::uint8_t *>(endian_data), midstate
        );

        log_debug(
            "Serial handler calculated midstate = " <<
            utility::to_hex(reinterpret_cast<std::uint8_t *> (&midstate[0]),
            reinterpret_cast<std::uint8_t *> (&midstate[0]) + sizeof(midstate))
        );

        /**
         * Append the midstate to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&midstate[0]),
			reinterpret_cast<std::uint8_t *> (&midstate[0]) + sizeof(midstate)
        );

        /**
         * Append the work to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&endian_data[0]) + 64,
			reinterpret_cast<std::uint8_t *> (&endian_data[0]) + 80
        );

        /**
         * The target.
         */
        std::uint32_t target = 504365055;
        
        /**
         * Append the target to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&target),
			reinterpret_cast<std::uint8_t *> (&target) + sizeof(target)
        );

		/**
		 * The end nonce.
		 */
		std::uint32_t nonce_end = std::numeric_limits<std::uint32_t>::max();

        /**
         * Append the nonce_end to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&nonce_end),
			reinterpret_cast<std::uint8_t *> (&nonce_end) + sizeof(nonce_end)
        );

		nonce_start_ = endian_data[19];

		log_debug(
			"Serial handler prepared (test mid-state), size = " << buffer.size()  <<
			", nonce = " << nonce_start_ << "."
		);

		assert(buffer.size() == 2 + work_length);

        i->write(
            reinterpret_cast<const char *> (&buffer[0]), buffer.size()
        );
    }
}

void serial_handler::send_test_work_midstate64_block_6947()
{
    if (auto i = serial_port_.lock())
    {
		/**
		 * The work length.
		 */
		enum { work_length = 88 };
        
        serial::message_t msg;
        
        msg.type = serial::message_type_test_work;
        msg.length = work_length;
            
        std::vector<std::uint8_t> buffer(2, 0);
            
        buffer[0] = msg.type;
        buffer[1] = msg.length;
        
		/**
		 * Test work (genesis block).
         * 64 bytes midstate (big-endian)
         * 20 (last) bytes of the work (big-endian)
         * 32-bit target (little-endian)
		 * 32-bit nonce_end (little-endian)
         *
         * std::uint32_t version;
         * std::uint8_t hash_previous_block[32];
         * std::uint8_t hash_merkle_root[32];
         * std::uint32_t timestamp;
         * std::uint32_t bits;
         * std::uint32_t nonce;
         *
         * version: 4
         * hash: 000000100b4df4467eff1cca4235382f2dfc4dc12f71764ec6fac0c96cd40500
         * time: 1419310800
         * nonce: 21383
         * bits: 1e0120db
         */
        auto block_header = utility::from_hex(
            "0400000053794489a630b48b60bde9c32cb70c82bf49a3fede4bb566821e3b396500"
			"0000cc96366316ff3bb81e21e0a68cf912a78e5d06bed48bb5d53e038a7ab42b877e"
			"3f2e9e5461f3001e00000000"
        );
        
		log_debug("size = " << block_header.size());

        assert(block_header.size() == 80);

        /**
         * Check genesis hash.
         */
        std::vector<std::uint8_t> digest(64, 0);
        
        /**
         * Hash the genesis block header.
         */
        hash::final(
            configuration::proof_of_work_type_whirlpool_xor,
            &block_header[0], block_header.size(), &digest[0]
        );
        
        std::reverse(&digest[0], &digest[0] + 32);

        /**
         * Get the hexidecimal representation of the digest.
         */
        auto hash = utility::to_hex(&digest[0], &digest[0] + 32);
        
		log_debug("hash = " << hash);

        /**
         * Validate the hash matches the genesis block hash.
         */
        assert(
            hash ==
            "f6ee76bc982b3396628c29bd157c6ccf7cc7957f09cfeb76a7b9e4ef6516e90a"
        );

        /**
         * Prepare the work.
         */
        auto ptr_data = reinterpret_cast<std::uint32_t *> (&block_header[0]);

        /**
         * The big endian data.
         */
        std::uint32_t endian_data[32];
        
		std::memcpy(endian_data, &block_header[0], 80);

        for (auto kk = 0; kk < 32; kk++)
        {
            utility::be32enc(&endian_data[kk], ((std::uint32_t *)ptr_data)[kk]);
        }

        utility::be32enc(&endian_data[19], ptr_data[19]);

        /**
         * Allocate the midstate.
         */
        std::uint64_t midstate[8];

        /**
         * Calculate midstate.
         */
        whirlpool_midstate(
            reinterpret_cast<const std::uint8_t *>(endian_data), midstate
        );

        log_debug(
            "Serial handler calculated midstate = " <<
            utility::to_hex(reinterpret_cast<std::uint8_t *> (&midstate[0]),
            reinterpret_cast<std::uint8_t *> (&midstate[0]) + sizeof(midstate))
        );

        /**
         * Append the midstate to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&midstate[0]),
			reinterpret_cast<std::uint8_t *> (&midstate[0]) + sizeof(midstate)
        );

        /**
         * Append the work to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&endian_data) + 64,
			reinterpret_cast<std::uint8_t *> (&endian_data) + 80
        );

        /**
         * The target.
         */
        std::uint32_t target = stratum_work_->target()[6];
        
        /**
         * Append the target to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&target),
			reinterpret_cast<std::uint8_t *> (&target) + sizeof(target)
        );

		/**
		 * The end nonce.
		 */
		std::uint32_t nonce_end = std::numeric_limits<std::uint32_t>::max();

        /**
         * Append the nonce_end to the message.
         */
        buffer.insert(
            buffer.end(), reinterpret_cast<std::uint8_t *> (&nonce_end),
			reinterpret_cast<std::uint8_t *> (&nonce_end) + sizeof(nonce_end)
        );

		nonce_start_ = endian_data[19];

		log_debug(
			"Serial handler prepared (test mid-state 6947), size = " << buffer.size()  <<
			", nonce = " << nonce_start_ << "."
		);

		assert(buffer.size() == 2 + work_length);

        i->write(
            reinterpret_cast<const char *> (&buffer[0]), buffer.size()
        );
	}
}
