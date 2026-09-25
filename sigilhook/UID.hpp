//
// Created by steve on 6/23/17.
//

#ifndef SIGILHOOK_UID_HPP
#define SIGILHOOK_UID_HPP

#include "sigilhook/SigilHookOs.hpp"
namespace SIGILHOOK {
	class UID {
	public:
		UID();
		UID(long val);
		static std::atomic_long& singleton();

		long val;
	};
}
#endif //SIGILHOOK_UID_HPP