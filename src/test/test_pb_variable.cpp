#include "depends/gtest/googletest/include/gtest/gtest.h"
#include "../sha256_verify.h"
//我们来实验下variable、linear_term、pb_variable、pb_variable_array、pb_linear_combination、pb_linear_combination_array是如何使用的
//目的：研究下protoboard中的Variable是如何排序的，如何区分公开输入、秘密输入

//首先是variable和linear_term类
//对于a*X_1+b*X_2....+n*X_i
//经过测试发现: 
//variable是对X_i的抽象，NOTE:variable只存索引(即i)，不存值
//linear_term即一次项，是对n*X_i的抽象，linear_term需要存储n的值和索引i
using namespace libsnark;
TEST(variable, linear_term)
{
	typedef libff::Fr<libff::default_ec_pp> FieldT;
	variable<FieldT> var;	
	
	linear_term<FieldT> lr = 1000*var; //1000*X_0, n==1000, i==0
	EXPECT_EQ(var.index, lr.index);
	EXPECT_EQ(FieldT(1000), lr.coeff);

	lr = -var;
	EXPECT_EQ(var.index, lr.index);
	EXPECT_EQ(FieldT(-1), lr.coeff);//-X_0

}

//linear_combination是对a*X_1+b*X_2....+n*X_i的抽象
TEST(variable, linear_combination)
{
	typedef libff::Fr<libff::default_ec_pp> FieldT;
	linear_combination<FieldT> lc; 
	lc.add_term(0, 10); //10*X_0
	lc.add_term(1, 11); //11*X_1
	lc.add_term(2, 13); //13*X_2

	EXPECT_EQ(size_t(3), lc.terms.size());
	EXPECT_EQ(size_t(0), lc.terms[0].index);
	EXPECT_EQ(size_t(1), lc.terms[1].index);
	EXPECT_EQ(size_t(2), lc.terms[2].index);
}
//下面来点复杂的，开始分析pb_variable
TEST(pb_variable, allocate)
{
	//pb_variable每次allocate都会:
        // 1. pb.next_free_var++  //记录一共allocate了多少次
	// 2. pb.values.emplace_back(FieldT::zero()); //该索引在value的末尾插入一个新值0
	//然后可以
	// 1. 通过索引为对应的value赋值

	typedef libff::Fr<libff::default_ec_pp> FieldT;
	pb_variable<FieldT> pv1;
	pb_variable<FieldT> pv2;

	protoboard<FieldT> pb;
	pv1.allocate(pb); //增加一个value
	EXPECT_EQ(size_t(1), pb.num_variables()); //pb的values大小现在为1. NOTE:variable只有索引，没有值哦
	EXPECT_EQ(size_t(0), pb.num_inputs()); //公开输入是0个. 

	pv2.allocate(pb); //再增加一个value
	EXPECT_EQ(size_t(2), pb.num_variables()); //pb的values大小现在为2
	EXPECT_EQ(size_t(0), pb.num_inputs()); //公开输入是还是0个，秘密的输入是2个

	//我们来看看这两个variable的索引
	EXPECT_EQ(size_t(1), pv1.index); //oh, pb从1开始分配索引
	EXPECT_EQ(size_t(2), pv2.index); //依次递增

	//我们再干点有意思的事情，虽然有点超出本次测试的范围
	pb.val(pv1) = 100;
	pb.val(pv2) = 11;
	EXPECT_EQ(pb.val(pv1), pb.val(pb_variable<FieldT>(pv1.index)));	
	EXPECT_EQ(pb.val(pv2), pb.val(pb_variable<FieldT>(pv2.index)));	//pv1和pv2不重要，重要的是pv1和pv2的索引，只有这个索引就能找到pb中对应的值

        //我们再把刚才赋的两个值100、11拿出来	
	r1cs_variable_assignment<FieldT>  values = pb.full_variable_assignment(); //把pb中的values都拿出来
	EXPECT_EQ(FieldT(100),values[0]); //oh, 第0个value对应的pb_variable的索引是1, 因为索引0对应的值不在values中存储
	EXPECT_EQ(FieldT(11),values[1]);
	EXPECT_EQ(size_t(2),values.size()); //allocate了两次，values的大小为2
}

//下面继续分析pb_variable_array
TEST(pb_variable_array, allocate)
{
	//pb_variable每次allocate只能新建一个索引（以及该索引对应的value空间），太慢了
	typedef libff::Fr<libff::default_ec_pp> FieldT;
	pb_variable_array<FieldT> pva;
	protoboard<FieldT> pb;

	pva.allocate(pb,10); //哈哈，一下分配了10个，索引0~9
	EXPECT_EQ(size_t(10), pb.num_variables()); //pb的values大小现在为10
	EXPECT_EQ(size_t(0), pb.num_inputs()); //公开输入是还是0个，秘密的输入是10个
	
	//既然有批量分配，那也有肯定也有批量赋值，如下:
	// 先初始化几个数据
	std::vector<FieldT> vals;
	for(int i = 0; i < 10; ++i)
	{
		vals.push_back(FieldT(i));
	}
	pva.fill_with_field_elements(pb, vals);
	for(int i = 0; i < 10; ++i)
	{
		EXPECT_EQ(FieldT(i), pb.val(pb_variable<FieldT>(i+1)));	 //索引(i+1)对应的values[i]的值
	}

	//测试下fill_with_bits_of_field_element方法
	pva.fill_with_bits_of_field_element(pb,FieldT(0x2));//二进制的10
	EXPECT_EQ(FieldT(0), pb.val(pb_variable<FieldT>(1))); //索引1对应0
	EXPECT_EQ(FieldT(1), pb.val(pb_variable<FieldT>(2))); //索引2对应1
}

TEST(pb_linear_combination, assign)
{
	//使用我们刚才的例子，先初始化一个linear_combination
	typedef libff::Fr<libff::default_ec_pp> FieldT;
	linear_combination<FieldT> lc; 
	lc.add_term(0, 10); //10*X_0
	lc.add_term(1, 11); //11*X_1
	lc.add_term(2, 13); //13*X_2
	EXPECT_EQ(size_t(3), lc.terms.size());
	EXPECT_EQ(size_t(0), lc.terms[0].index);
	EXPECT_EQ(size_t(1), lc.terms[1].index);
	EXPECT_EQ(size_t(2), lc.terms[2].index);


	protoboard<FieldT> pb;
	pb_linear_combination<FieldT> plc;
	plc.assign(pb, lc); //plc.terms = lc.terms, pb.next_free_lc++, pb.lc_values.emplace_back(FieldT::zero()), lc_values开辟了一个空间，并赋初始值0;

	pb_variable_array<FieldT> pva;
	pva.allocate(pb,3); //pb的values并没有空间，需要在这里开辟

	pb.val(pb_variable<FieldT>(lc.terms[0].index))= FieldT(5); //有了空间，才能赋值
	pb.val(pb_variable<FieldT>(lc.terms[1].index))= FieldT(6);
	pb.val(pb_variable<FieldT>(lc.terms[2].index))= FieldT(7);

	EXPECT_EQ(FieldT(0), pb.lc_val(plc));//求和前,拿出lc_values中的值
	plc.evaluate(pb); //求和sum = 10*5+11*6+13*7；
	EXPECT_EQ(FieldT(10*5+11*6+13*7), pb.lc_val(plc));//求和后,拿出lc_values中的值
	
	//这代码写的我是无语了 太乱了
}

//测一下SHA256_default_IV方法究竟有何效果
TEST(other, SHA256_default_IV)
{
	typedef libff::Fr<libff::default_ec_pp> FieldT;
	//先测下10*ONE的类型
	linear_term<FieldT> lt = 10*ONE;
	EXPECT_EQ(size_t(0), lt.index);
	EXPECT_EQ(FieldT(10), lt.coeff);

	linear_combination<FieldT> lc = 10*ONE;
	EXPECT_EQ(size_t(1), lc.terms.size());
	EXPECT_EQ(size_t(0), lc.terms[0].index);
	EXPECT_EQ(FieldT(10), lc.terms[0].coeff);

	protoboard<FieldT> pb;
	pb_linear_combination_array<FieldT> plca = SHA256_default_IV(pb);
	/*
	* pb_linear_combination_array: 第一个元素：index=0 ,coeff= , val= X_0;后续index递增，coeff由SHA256_H计算得来，val不变，一共256个
	* pb: lc_values：即SHA256_H的二进制展开，每个比特位占一个位置
	*/
	//TODO check result
}

//还差一个pb_linear_combination_array，我不想测了，里边放的是vector<pb_linear_combination>
