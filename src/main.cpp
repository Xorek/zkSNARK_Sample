#include <libsnark/gadgetlib2/examples/simple_example.hpp>
#include <libsnark/gadgetlib2/gadget.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib2/integration.hpp>

using namespace gadgetlib2;
using namespace libsnark;

//start: 最简单的一个例子,展示底层的工作流程
int very_easy_sample()
{
	typedef libff::Fr<libff::default_ec_pp> FieldT;	
	typedef libff::default_ec_pp ppT;	

	// Initialize prime field parameters. This is always needed for R1P. 
	//1.可信第三方:初始化生成椭圆曲线的公共参数?
	libff::default_ec_pp::init_public_params();
	//initPublicParamsFromDefaultPp();
	//1. end
	
	//2.生成约束。约束内容:a*(5+c) == d 且 b == d. NOTE:生成约束的过程任何人都可以做，约束本身是公开的
	// The protoboard is the 'memory manager' which holds all constraints (when creating the
	// verifying circuit) and variable assignments (when creating the proof witness). We specify
	// the type as R1P, this can be augmented in the future to allow for BOOLEAN or GF2_EXTENSION
	// fields in the future.
	ProtoboardPtr pb = Protoboard::create(R1P);
	// We now create 3 input variables and one output
	VariableArray input(3, "input");//Variable内部有索引,按照生成顺序进行排序
	Variable output("output");
	// We can now add some constraints. The string is for debugging purposes and can be a textual
	// description of the constraint
	pb->addRank1Constraint(input[0], 5 + input[2], output,
			"Constraint 1: input[0] * (5 + input[2]) == output");
	// The second form addUnaryConstraint(LinearCombination) means (LinearCombination == 0).
	pb->addUnaryConstraint(input[1] - output,
			"Constraint 2: input[1] - output == 0");
	//转换成libsnark可识别的约束系统
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
	//2. end

	//3. 可信第三方生成pk和vk
	//生成pk和vk
	r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(cs);
	//vk再处理
	r1cs_ppzksnark_processed_verification_key<ppT> pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

	//4. 证明者提供可以满足约束的赋值. NOTE:证明者需要先拿到第二步的产生的约束
	pb->val(input[2]) = 37; // 1 * (5 + 37) == 42
	pb->val(input[0]) = 1;
	pb->val(input[1]) = pb->val(output) = 42; // input[1] - output == 0
	//4. end

        //5. 证明者将赋值做一些转化	
	//将第四步的赋值提取出来，并做一定的转化
	const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
	/* 也可以直接对full_assignment进行赋值，赋值顺序匹配索引顺序
	r1cs_variable_assignment<FieldT> full_assignment;
	full_assignment.push_back(FieldT(1));
	full_assignment.push_back(FieldT(42));
	full_assignment.push_back(FieldT(37));
	full_assignment.push_back(FieldT(42));
	*/
	//定义哪些赋值是公开的. NOTE:默认是0个公开赋值
	const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(), full_assignment.begin() + cs.num_inputs());
	//定义哪些赋值是秘密的
	const r1cs_auxiliary_input<FieldT> auxiliary_input(full_assignment.begin() + cs.num_inputs(), full_assignment.end());
	//将cs、公开的输入、秘密的输入打包，这个操作也可以不做
        //r1cs_example<FieldT> r1cs = r1cs_example<FieldT>(cs, primary_input, auxiliary_input);
        //5. end
	
	assert(cs.is_valid());
	assert(cs.is_satisfied(primary_input, auxiliary_input));

	//6. 证明者生成证明	
	//证明者:生成证明，输入：pk、公开输入、秘密输入
	r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(keypair.pk, primary_input, auxiliary_input);	
	//6. end
	
	//7. 验证者进行验证，输入：vk、公开的输入、证明
	const bool ans = r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, primary_input, proof);
	printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
	/* 另一个验证方法，和上面验证方法的结果应该一致
	const bool ans2 = r1cs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, primary_input, proof);
	*/
	//assert(ans == ans2);
	//7. end
	return 0;
}
//end: 最简单的一个例子

//start: 一个复杂的例子，封装一个用于检验SHA1的零知识证明. 看这个例子前，请先看libsnark/gadgetlib2/examples/tutorial.cpp文件.
/*
CREATE_GADGET_BASE_CLASS(SHA1_GadgetBase);

SHA1_GadgetBase::~SHA1_GadgetBase(){};

class SHA1_Gadget : public SHA1_GadgetBase
{
	private:
		
}
*/
//end: 一个复杂的例子

int main()
{
	very_easy_sample();
}