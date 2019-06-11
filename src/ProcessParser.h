#include <dirent.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include "constants.h"
#include "util.h"

using namespace std;

class ProcessParser {
   private:
    ifstream stream;

   public:
    static string getCmd(string pid);
    static vector<string> getPidList();
    static string getVmSize(string pid);
    static string getCpuPercent(string pid);
    static long int getSysUpTime();
    static string getProcUpTime(string pid);
    static string getProcUser(string pid);
    static vector<string> getSysCpuPercent(string coreNumber = "");
    static float getSysRamPercent();
    static string getSysKernelVersion();
    static int getNumberOfCores();
    static int getTotalThreads();
    static int getTotalNumberOfProcesses();
    static int getNumberOfRunningProcesses();
    static string getOSName();
    static string printCpuStats(vector<string> values1, vector<string> values2);
    static bool isPidExisting(string pid);
};

string ProcessParser::getCmd(string pid) {
    string line;
    ifstream stream;
    string path = Path::basePath() + pid + Path::cmdPath();
    Util::getStream(path, stream);
    getline(stream, line);

    return line;
}

string ProcessParser::getVmSize(string pid) {
    string line;
    string name = "VmData";
    string value;

    float result;

    ifstream stream;
    string path = Path::basePath() + pid + Path::statusPath();
    Util::getStream(path, stream);

    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);

            result = (stof(values[1]) / float(1024));
            break;
        }
    };

    return to_string(result);
}

string ProcessParser::getCpuPercent(string pid) {
    string line;
    string value;
    ifstream stream;
    string path = Path::basePath() + pid + Path::statPath();

    Util::getStream(path, stream);
    getline(stream, line);

    string str = line;
    istringstream buf(str);
    istream_iterator<string> beg(buf), end;
    vector<string> values(beg, end);

    float u_time = stof(ProcessParser::getProcUpTime(pid));
    float s_time = stof(values[14]);
    float cu_time = stof(values[15]);
    float cs_time = stof(values[16]);
    float start_time = stof(values[21]);
    float up_time = ProcessParser::getSysUpTime();
    float freq = sysconf(_SC_CLK_TCK);
    float total_time = up_time + s_time + cu_time + cs_time;
    float seconds = up_time - (start_time / freq);

    float result = 100.0 * ((total_time / freq) / seconds);

    return to_string(result);
}

string ProcessParser::getProcUpTime(string pid) {
    string line;
    string value;
    ifstream stream;
    string path = Path::basePath() + pid + Path::statPath();

    Util::getStream(path, stream);
    getline(stream, line);

    string str = line;
    istringstream buf(str);
    istream_iterator<string> beg(buf), end;
    vector<string> values(beg, end);

    return to_string(float(stof(values[13]) / sysconf(_SC_CLK_TCK)));
}

long int ProcessParser::getSysUpTime() {
    string line;
    ifstream stream;
    string path = Path::basePath() + Path::upTimePath();

    Util::getStream(path, stream);
    getline(stream, line);

    istringstream buf(line);
    istream_iterator<string> beg(buf), end;
    vector<string> values(beg, end);

    return stoi(values[0]);
}

string ProcessParser::getProcUser(string pid) {
    string line;
    string name = "Uid";
    string result = "";

    ifstream stream;
    string path = Path::basePath() + pid + Path::statusPath();

    Util::getStream(path, stream);

    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);

            result = values[1];
            break;
        }
    };

    ifstream another_stream;
    Util::getStream("/etc/passwd", another_stream);
    name = ("x:" + result);

    while (getline(another_stream, line)) {
        if (line.find(name) != string::npos) {
            result = line.substr(0, line.find(":"));
            return result;
        }
    }

    return "";
}

// come back to this later.
vector<string> ProcessParser::getPidList() {
    DIR* dir;

    // Basically, we are scanning /proc dir for all directories with numbers as their names
    // If we get valid check we store dir names in vector as list of machine pids
    vector<string> container;

    if (!(dir = opendir("/proc"))) {
        throw runtime_error(strerror(errno));
    }

    while (dirent* dirp = readdir(dir)) {
        // is this a directory?
        if (dirp->d_type != DT_DIR) {
            continue;
        }
        // Is every character of the name a digit?
        if (all_of(dirp->d_name, dirp->d_name + strlen(dirp->d_name), [](char c) { return isdigit(c); })) {
            container.push_back(dirp->d_name);
        }
    }

    // Validating process of directory closing
    if (closedir(dir)) {
        throw runtime_error(strerror(errno));
    }

    return container;
}

int ProcessParser::getNumberOfCores() {
    // Get the number of host cpu cores
    string line;
    ifstream stream;
    string name = "cpu cores";
    Util::getStream((Path::basePath() + "cpuinfo"), stream);

    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);

            return stoi(values[3]);
            // break?
        }
    }

    return 0;
}

vector<string> ProcessParser::getSysCpuPercent(string coreNumber) {
    string line;
    string name = "cpu" + coreNumber;
    string value;
    int result;

    ifstream stream;
    string path = Path::basePath() + Path::statPath();

    Util::getStream(path, stream);

    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);

            // set of cpu data active and idle times;
            return values;
        }
    }

    return (vector<string>());
}

float getSysActiveCpuTime(vector<string> values) {
    return (stof(values[S_USER]) +
            stof(values[S_NICE]) +
            stof(values[S_SYSTEM]) +
            stof(values[S_IRQ]) +
            stof(values[S_SOFTIRQ]) +
            stof(values[S_STEAL]) +
            stof(values[S_GUEST]) +
            stof(values[S_GUEST_NICE]));
}

float getSysIdleCpuTime(vector<string> values) {
    return (stof(values[S_IDLE]) + stof(values[S_IOWAIT]));
}

string ProcessParser::printCpuStats(vector<string> values1, vector<string> values2) {
    float activeTime = getSysActiveCpuTime(values2) - getSysActiveCpuTime(values1);
    float idleTime = getSysIdleCpuTime(values2) - getSysIdleCpuTime(values1);
    float totalTime = activeTime + idleTime;
    float result = 100.0 * (activeTime / totalTime);

    return to_string(result);
}

float ProcessParser::getSysRamPercent() {
    string line;
    string name1 = "MemAvailable:";
    string name2 = "MemFree:";
    string name3 = "Buffers:";

    string value;
    int result;
    ifstream stream;
    Util::getStream((Path::basePath() + Path::memInfoPath()), stream);

    float total_mem = 0;
    float free_mem = 0;
    float buffers = 0;

    while (getline(stream, line)) {
        if (total_mem != 0 && free_mem != 0)
            break;

        if (line.compare(0, name1.size(), name1) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            total_mem = stof(values[1]);
        }

        if (line.compare(0, name2.size(), name2) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            free_mem = stof(values[1]);
        }

        if (line.compare(0, name3.size(), name3) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            buffers = stof(values[1]);
        }
    }

    return float(100.0 * (1 - (free_mem / (total_mem - buffers))));
}

string ProcessParser::getSysKernelVersion() {
    string line;
    string name = "Linux version ";
    ifstream stream;
    Util::getStream((Path::basePath() + Path::versionPath()), stream);

    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);

            return values[2];
        }
    }

    return "";
}

string ProcessParser::getOSName() {
    string line;
    string name = "PRETTY_NAME=";

    ifstream stream;
    Util::getStream(("/etc/os-release"), stream);

    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            size_t found = line.find("=");
            found++;
            string result = line.substr(found);
            result.erase(remove(result.begin(), result.end(), '"'), result.end());

            return result;
        }
    }

    return "";
}

int ProcessParser::getTotalThreads() {
    string line;
    int result = 0;
    string name = "Threads:";
    vector<string> _list = ProcessParser::getPidList();

    for (int i = 0; i < _list.size(); i++) {
        string pid = _list[i];

        ifstream stream;
        string path = Path::basePath() + pid + Path::statusPath();
        Util::getStream(path, stream);

        while (getline(stream, line)) {
            if (line.compare(0, name.size(), name) == 0) {
                istringstream buf(line);
                istream_iterator<string> beg(buf), end;
                vector<string> values(beg, end);
                result += stoi(values[1]);

                break;
            }
        }

        return result;
    }
}

int ProcessParser::getTotalNumberOfProcesses() {
    string line;
    int result = 0;
    string name = "processes";

    ifstream stream;
    string path = Path::basePath() + Path::statPath();
    Util::getStream(path, stream);

    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            result += stoi(values[1]);

            break;
        }
    }

    return result;
}

int ProcessParser::getNumberOfRunningProcesses() {
    string line;
    int result = 0;
    string name = "procs_running";

    ifstream stream;
    string path = Path::basePath() + Path::statPath();
    Util::getStream(path, stream);

    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            result += stoi(values[1]);

            break;
        }
    }

    return result;
}
