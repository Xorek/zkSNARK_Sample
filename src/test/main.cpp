#include "depends/gtest/googletest/include/gtest/gtest.h"
#include "../sha256_verify.h"
using namespace libsnark;
//zkSNARK自带的例子，用来测试我们的环境是否正常
TEST(sha256_two_to_one_hash_gadget, zsSNARK_sha256_sample)
{
	typedef libff::Fr<libff::default_ec_pp> FieldT;
	protoboard<FieldT> pb;

	digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
	digest_variable<FieldT> right(pb, SHA256_digest_size, "right");
	digest_variable<FieldT> output(pb, SHA256_digest_size, "output");

	sha256_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");
	f.generate_r1cs_constraints();
	printf("Number of constraints for sha256_two_to_one_hash_gadget: %zu\n", pb.num_constraints());

	const libff::bit_vector left_bv = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
	const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
	const libff::bit_vector hash_bv = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);

	left.generate_r1cs_witness(left_bv);
	right.generate_r1cs_witness(right_bv);

	f.generate_r1cs_witness();
	output.generate_r1cs_witness(hash_bv);

	EXPECT_TRUE(pb.is_satisfied());
}
//下面，我们使用sha256_two_to_one_hash_gadget的另一个构造函数，不仅自定义new block，还自定义pre output
TEST(sha256_two_to_one_hash_gadget, custom_two_value_and_one_is_default)
{
	typedef libff::Fr<libff::default_ec_pp> FieldT;
	protoboard<FieldT> pb;
	
	//变量初始化
        pb_linear_combination_array<FieldT> pre_output(SHA256_digest_size);//pre output
        pre_output = SHA256_default_IV<FieldT>(pb);//pre output
	block_variable<FieldT> new_block(pb,SHA256_block_size,"new_block"); // new block
	digest_variable<FieldT> expect_output(pb, SHA256_digest_size, "block"); //expect output
	//变量就位
        const std::string prefix = "f";
	sha256_two_to_one_hash_gadget<FieldT> f(pb,pre_output,new_block,expect_output,prefix);
	//构建约束
	f.generate_r1cs_constraints();
	
	//为变量赋值 
        //pre_output = SHA256_default_IV<FieldT>(pb);//pre output
	const libff::bit_vector block_content = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9,
								0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
	new_block.generate_r1cs_witness(block_content); // new block
	f.generate_r1cs_witness();

	const libff::bit_vector expect_content = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);
	expect_output.generate_r1cs_witness(expect_content); //expect_output
	
	EXPECT_TRUE(pb.is_satisfied());
}

//very good，下面我们可以试试计算sha(1)，手动填充sha256的附加长度
//sha256(1) == 0x6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
//求1的哈希，只需计算一轮
TEST(sha256_two_to_one_hash_gadget, check_1_hash)
{
	typedef libff::Fr<libff::default_ec_pp> FieldT;
	protoboard<FieldT> pb;
	
	//变量初始化
        pb_linear_combination_array<FieldT> pre_output(SHA256_digest_size);//pre output仍使用默认值
        pre_output = SHA256_default_IV<FieldT>(pb);//pre output
	block_variable<FieldT> new_block(pb,SHA256_block_size,"new_block"); // new block
	digest_variable<FieldT> expect_output(pb, SHA256_digest_size, "block"); //expect output
	//变量就位
        const std::string prefix = "f";
	sha256_two_to_one_hash_gadget<FieldT> f(pb,pre_output,new_block,expect_output,prefix);
	//构建约束
	f.generate_r1cs_constraints();

	//为变量赋值 
        //pre_output = SHA256_default_IV<FieldT>(pb);//pre output
	//按照sha2算法的规则，手动补位，规则见:https://blog.csdn.net/u011583927/article/details/80905740
	const libff::bit_vector block_content = libff::int_list_to_bits({0x31800000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
								0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8}, 32);
	new_block.generate_r1cs_witness(block_content); // new block
	f.generate_r1cs_witness();

	const libff::bit_vector expect_content = libff::int_list_to_bits({0x6b86b273,0xff34fce1,0x9d6b804e,0xff5a3f57,0x47ada4ea,0xa22f1d49,0xc01e52dd,0xb7875b4b}, 32);
	
	expect_output.generate_r1cs_witness(expect_content); //expect_output

	/*	
	std::cout<<pb.auxiliary_input().size()<<std::endl;
	std::cout<<pb.primary_input().size()<<std::endl;
	std::cout<<"start"<<std::endl;
	std::cout<<pb.full_variable_assignment()<<std::endl;
	std::cout<<"end"<<std::endl;
	*/
	
	EXPECT_TRUE(pb.is_satisfied());
}
int main(int argc, char **argv) {
    libff::default_ec_pp::init_public_params(); //一定要做
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
