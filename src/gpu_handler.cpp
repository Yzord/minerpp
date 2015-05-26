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

#include <miner/gpu.hpp>
#include <miner/gpu_handler.hpp>
#include <miner/logger.hpp>
#include <miner/stratum_work.hpp>
#include <miner/utility.hpp>

using namespace miner;

gpu_handler::gpu_handler(std::shared_ptr<gpu> owner)
    : should_run_(false)
    , gpu_(owner)
{
    // ...
}

void gpu_handler::on_read(const char * buf, const std::size_t & len)
{
    assert(0);
}

void gpu_handler::set_has_new_work(const bool & val)
{
    assert(0);
}

void gpu_handler::set_needs_work_restart(const bool & val)
{
    assert(0);
}

void gpu_handler::run()
{
    assert(0);
}

bool gpu_handler::prepare_work(std::uint32_t * val)
{
    if (auto i = gpu_.lock())
    {
        std::lock_guard<std::mutex> l1(mutex_work_);
        
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

				log_debug(
					"GPU handler prepared nonce = " << val[19] << "."
				);

				return true;
			}
		}
    }

    return false;
}