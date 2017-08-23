/*
 * Iptables.h
 *
 *  Created on: Aug 20, 2017
 *      Author: steven
 */

#ifndef IPTABLES_H_
#define IPTABLES_H_

#include <fstream>

#include <syslog.h>
class Iptables {
private:
    bool Debug;

public:
    Iptables(){
    }
    ~Iptables() {
        // TODO Auto-generated destructor stub
    }
};

#endif /* IPTABLES_H_ */
