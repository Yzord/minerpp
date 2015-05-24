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

#ifndef MINER_GPU_HANDLER_OPENCL_HPP
#define MINER_GPU_HANDLER_OPENCL_HPP

#include <cstdint>
#include <memory>
#include <string>

#define USE_OPENCL 0

#if (defined USE_OPENCL && USE_OPENCL)
#include <OpenCL/opencl.h>
#endif // USE_OPENCL

#include <miner/gpu_handler.hpp>
#include <miner/logger.hpp>
#include <miner/stratum_work.hpp>

namespace miner {

    class gpu;
    
    /**
     * Implements a GPU handler for OpenCL.
     */
    class gpu_handler_opencl : public gpu_handler
    {
        public:
        
            enum { buffer_size = sizeof(std::uint32_t) * 0x100 };
        
            /**
             * Constructor
             * @param owner The gpu.
             */
            explicit gpu_handler_opencl(std::shared_ptr<gpu> owner)
                : gpu_handler(owner)
            {
                // ...
            }
        
            /**
             * Starts
             */
            virtual void start()
            {
#if (defined USE_OPENCL && USE_OPENCL)
                if (
                    clGetDeviceIDs(0, CL_DEVICE_TYPE_GPU, 1,
                    &cl_device_id_, 0) != CL_SUCCESS
                    )
                {
                    throw std::runtime_error("clGetDeviceIDs failed");
                }
                
                auto error = 0;
                
                cl_context_ = clCreateContext(
                    0, 1, &cl_device_id_, 0, 0, &error
                );
    
                if (cl_context_ == 0)
                {
                    throw std::runtime_error("clCreateContext failed");

                }

                cl_command_queue_ = clCreateCommandQueue(
                    cl_context_, cl_device_id_, 0, &error
                );
    
                if (cl_command_queue_ == 0)
                {
                    throw std::runtime_error("clCreateCommandQueue failed");
                }
                
                const char * g_kernel_source_whirlpool =
                    "\n"
                ;

                cl_program_ = clCreateProgramWithSource(
                    cl_context_, 1, (const char **)&g_kernel_source_whirlpool,
                    0, &error
                );
                
                if (cl_program_ == 0)
                {
                    throw std::runtime_error(
                        "clCreateProgramWithSource failed"
                    );
                }
                
                error = clBuildProgram(cl_program_, 0, 0, 0, 0, 0);
                
                if (error != CL_SUCCESS)
                {
                    std::size_t len;
                    
                    char buf[2048 * 8];

                    clGetProgramBuildInfo(
                        cl_program_, cl_device_id_, CL_PROGRAM_BUILD_LOG,
                        sizeof(buf), buf, &len
                    );
                    
                    log_error(
                        "GPU handler OpenCL clBuildProgram failed, "
                        "ProgramBuildInfo = " << std::string(buf, len) << "."
                    );

                    throw std::runtime_error("clBuildProgram failed");
                }
    
                cl_kernel_ = clCreateKernel(cl_program_, "search", &error);
                
                if (cl_kernel_ == 0 || error != CL_SUCCESS)
                {
                    throw std::runtime_error("clCreateKernel failed");
                }

                cl_mem_input_ = clCreateBuffer(
                    cl_context_, CL_MEM_READ_ONLY,
                    sizeof(float) * buffer_size,
                    0, 0
                );
                
                cl_mem_output_ = clCreateBuffer(
                    cl_context_, CL_MEM_WRITE_ONLY,
                    sizeof(float) * buffer_size, 0, 0
                );
                
                if (cl_mem_input_ == 0 || cl_mem_output_ == 0)
                {
                    throw std::runtime_error("clCreateBuffer failed");
                }
#endif // USE_OPENCL
            }
        
            /**
             * Stops
             */
            virtual void stop()
            {
#if (defined USE_OPENCL && USE_OPENCL)
                if (cl_program_)
                {
                    clReleaseProgram(cl_program_);
                }
                
                if (cl_kernel_)
                {
                    clReleaseKernel(cl_kernel_);
                }
                
                if (cl_context_)
                {
                    clReleaseContext(cl_context_);
                }
                
                if (cl_command_queue_)
                {
                    clReleaseCommandQueue(cl_command_queue_);
                }
#endif // USE_OPENCL
            }
        
            /**
             * The read handler.
             * @param buf The buffer.
             * @param len The length.
             */
            virtual void on_read(const char * buf, const std::size_t & len)
            {
                assert(0);
            }
        
            /**
             * Sets that new work is available.
             * @param val The value.
             */
            virtual void set_has_new_work(const bool & val)
            {
                if (prepare_work(endian_data_))
                {
                    should_run_ = true;
                }
            }
        
            /**
             * Sets that new work is available.
             * @param val The value.
             */
            virtual void set_needs_work_restart(const bool & val)
            {
                // ...
            }
        
            /**
             * Runs the loop.
             */
            virtual void run()
            {
                // ...
            }
        
        private:
        
            // ...
        
        protected:
#if (defined USE_OPENCL && USE_OPENCL)
            /**
             * The cl_device_id.
             */
            cl_device_id cl_device_id_;
        
            /**
             * The cl_context.
             */
            cl_context cl_context_;
        
            /**
             * The cl_command_queue.
             */
            cl_command_queue cl_command_queue_;
        
            /**
             * The cl_program.
             */
            cl_program cl_program_;
        
            /**
             * The cl_kernel.
             */
            cl_kernel cl_kernel_;
        
            /**
             * The cl_mem input.
             */
            cl_mem cl_mem_input_;
        
            /**
             * The cl_mem output.
             */
            cl_mem cl_mem_output_;
#endif // USE_OPENCL
    };
    
} // namespace miner

#endif // MINER_GPU_HANDLER_OPENCL_HPP
