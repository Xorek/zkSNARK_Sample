#include "easy_sample.h"
#include "sha256_verify.h"
/*
#include <libsnark/gadgetlib2/examples/simple_example.hpp>
#include <libsnark/gadgetlib2/gadget.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib2/integration.hpp>

using namespace gadgetlib2;
using namespace libsnark;
*/

//start: 最简单的一个例子,展示底层的工作流程
//本例基于libsnark/gadgetlib2目录下的工具类，如Protoboard类、get_variable_assignment_from_gadgetlib2方法等
//libsnark/gadgetlib1目录下也有类似的工具类，但实现风格不太一样。
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
