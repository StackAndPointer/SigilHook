#ifndef SIGILHOOK_EFFECTSTRACKER_HPP
#define SIGILHOOK_EFFECTSTRACKER_HPP

#include "../UID.hpp"

class Effect {
public:
	Effect();

	Effect& operator=(const Effect& rhs);

	void trigger();

	bool didExecute();
private:
	bool m_executed;
	SIGILHOOK::UID m_uid;
};

/**Track if some side effect happened.**/
class EffectTracker {
public:
	void PushEffect();
	Effect PopEffect();
	Effect& PeakEffect();
private:
	std::vector<Effect> m_effectQ;
};
#endif