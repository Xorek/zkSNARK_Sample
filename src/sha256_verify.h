#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

using namespace libsnark;
/*
template<typename FieldT>
class sha256_two_to_one_hash_custom_input_gadget : public sha256_two_to_one_hash_gadget<FieldT>
{
	public:
		sha256_two_to_one_hash_custom_input_gadget(protoboard<FieldT> &pb,
				const digest_variable<FieldT> &left,
				const digest_variable<FieldT> &right,
				const digest_variable<FieldT> &output,
				const std::string &annotation_prefix):sha256_two_to_one_hash_gadget<FieldT>(pb,left,right,output,annotation_prefix)
		{
			//do nothing
		}
		sha256_two_to_one_hash_custom_input_gadget(protoboard<FieldT> &pb,
				const size_t block_length,
				const block_variable<FieldT> &input_block,
				const digest_variable<FieldT> &output,
				const std::string &annotation_prefix):sha256_two_to_one_hash_gadget<FieldT>(pb,block_length,input_block,output,annotation_prefix)
		{
			//do nothing
		}
		sha256_two_to_one_hash_custom_input_gadget(protoboard<FieldT> &pb,
				//const block_variable<FieldT> &input_block_1,
				const pb_linear_combination_array<FieldT> &pre_output,
				const block_variable<FieldT> &new_block,
				const digest_variable<FieldT> &output,
				const std::string &annotation_prefix)//:sha256_two_to_one_hash_gadget<FieldT>(pb,pre_output,new_block.bits,output,annotation_prefix)
		{
			assert(pre_output.bits.size() == SHA256_digest_size);//pre_output是最新的中间计算结果. SHA256_digest_size == 256
			assert(new_block.bits.size() == SHA256_block_size); //new_block是即将参与计算的下一个数据块. SHA256_block_size == 512
			sha256_two_to_one_hash_gadget<FieldT>::f.reset(new sha256_compression_function_gadget<FieldT>(pb, pre_output, new_block.bits, output, FMT(annotation_prefix, " f")));
		}	
};
*/
