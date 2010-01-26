/* clipsniff/clipsniff.cc
 *
 * ClipSniff
 *
 * By Thomas Habets <thomas@habets.pp.se>
 *
 * Sniff the X11 clipboards
 *
 */
/*
 *  Copyright (C) 2010 Thomas Habets <thomas@habets.pp.se>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>

#include <sqlite3.h>

#include <X11/Xlib.h>
#include <X11/Xatom.h>

#define BEGIN_NAMESPACE(x) namespace x {
#define END_NAMESPACE(x) }

BEGIN_NAMESPACE();
std::string argv0;

/**
 *
 */
void
printVersion()
{
        printf("Copyright (C) 2010 Thomas Habets\n"
               "License GPLv2: GNU GPL version 2 or later "
               "<http://gnu.org/licenses/gpl-2.0.html>\n"
               "This is free software: you are free to change and "
               "redistribute it.\n"
               "There is NO WARRANTY, to the extent permitted by law.\n");
        exit(EXIT_SUCCESS);
}

/**
 *
 */
void
usage(int err)
{
        printf("Usage: %s [ -hV ] [ -d <display> ] [ -w <filename> ]\n"
               "\n"
               "\t-d <display>     Select display. Default to $DISPLAY\n"
               "\t-h, --help       Show this help text\n"
               "\t-V, --version    Show version.\n"
               "\t-w <filename>    Output sqlite database\n"
               "\n"
               "Report bugs to: thomas@habets.pp.se\n"
               "ClipSniff home page: <http://www.habets.pp.se/synscan/>\n"
               "Development repo: http://github.com/ThomasHabets/clipsniff\n"
               , argv0.c_str());
        exit(err);
}

/**
 *
 */
class ErrBase: public std::exception {
        const std::string msg;
public:
        ErrBase(const std::string &msg):msg(msg)  {   }
        const char *what() const throw() { return msg.c_str(); }
        ~ErrBase() throw() {};
};

END_NAMESPACE();

/**
 *
 */
class ClipSniff {
        Display *display;
        std::string displayName;
        Window myWindow;

        Atom getAtom(const std::string &atom);
public:
        ClipSniff(const std::string &display);
        std::string getData(const std::string &atom = "PRIMARY");
        std::pair<std::string, std::string> get();

        std::string getOwner(const std::string &atom = "PRIMARY");
        std::pair<std::string,std::string> getOwners();
};

/**
 * get name of clipboard owner as a string. E.g. "Firefox"
 * "which" is either "PRIMARY" (default) or "CLIPBOARD".
 */
std::string
ClipSniff::getOwner(const std::string &which)
{
        Atom atom = getAtom(which);
        std::string atomName = XGetAtomName(display, atom);
        Window win;
        char *windowName;
        if (None == (win = XGetSelectionOwner(display, atom))) {
                throw ErrBase("Can't get selection owner");
        }
        XFetchName(display, win, &windowName);
        std::string ret(windowName);
        XFree(windowName);
        return ret;
}

/**
 * Get both clipboards as a pair
 */
std::pair<std::string, std::string>
ClipSniff::get()
{
        return std::pair<std::string, std::string>(getData(),
                                                   getData("CLIPBOARD"));
}

/**
 * Get both clipboard owners as a pair
 */
std::pair<std::string, std::string>
ClipSniff::getOwners()
{
        return std::pair<std::string, std::string>(getOwner(),
                                                   getOwner("CLIPBOARD"));
}

/**
 * get the X11 atom with a given name.
 */
Atom
ClipSniff::getAtom(const std::string &which)
{
        Atom a;
        if((a = XInternAtom(display, which.c_str(), True)) == None) {
                throw ErrBase(std::string("Can't find atom: ") + which);
        }
        return a;
}

/**
 * get the data in a given clipboard ("PRIMARY" or "CLIPBOARD")
 *
 * FIXME: timeout
 */
std::string
ClipSniff::getData(const std::string &atom)
{
        // request selection
        XConvertSelection(display,
                          getAtom(atom), // atom,
                          XA_STRING, // type?
                          XA_STRING, // prop,
                          myWindow,
                          CurrentTime);

        // wait for the event
        XEvent report;
        unsigned char *buf = 0;
        Atom type;
        int format;
        unsigned long nitems, bytes;
        for(;;) {
                XNextEvent(display, &report);
                switch  (report.type) {
                case SelectionNotify:
                        if (report.xselection.property == None) {
                                return "";
                        }
                        XGetWindowProperty(display,
                                           myWindow,
                                           report.xselection.property,
                                           0, // offset
                                           (~0L), // length
                                           False, // delete
                                           AnyPropertyType, // reg_type
                                           &type,// *actual_type_return,
                                           &format,// *actual_format_return
                                           &nitems,// *nitems_return
                                           &bytes, // *bytes_after_return
                                           &buf// **prop_return);
                                           );
                        return (const char*)buf;
                default:
                        //printf("other %d...\n", report.type);
                        ;
                }
        }
}

/**
 * init X11 communication:
 *  1) connect
 *  2) create window (will not be displayed)
 */
ClipSniff::ClipSniff(const std::string &displ)
        :displayName(displ)
{
        const char *display_cstr = NULL;
        if (!displayName.empty()) {
                display_cstr = displayName.c_str();
        }
        if(!(display = XOpenDisplay(display_cstr))) {
                throw ErrBase(std::string("Error opening display: ")
                              + XDisplayName(display_cstr));
        }
        
        int screen_num = DefaultScreen(display);
        myWindow = XCreateSimpleWindow(display,
                                       RootWindow(display, screen_num),//parent
                                       100, 100, // pos
                                       100, 100, //  size
                                       10,  // border width
                                       BlackPixel(display, screen_num),
                                       WhitePixel(display, screen_num)
                                       );
        if (!myWindow) {
                throw ErrBase("Failed to create window");
        }
}

BEGIN_NAMESPACE();

/**
 *
 */
void
saveDb(const std::string &which,
       const std::string &data,
       const std::string &owner,
       sqlite3_stmt *stmt)
{
        sqlite3_reset(stmt);

        char timebuf[1024];
        struct tm tm;
        time_t ti;
        time(&ti);
        localtime_r(&ti, &tm);
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);

        if (SQLITE_OK != sqlite3_bind_text(stmt,1,
                                           timebuf,strlen(timebuf),
                                           SQLITE_TRANSIENT)) {
                throw ErrBase("sqlite3_bind_text(1)");
        }
        if (SQLITE_OK != sqlite3_bind_text(stmt,2,
                                           which.c_str(),which.size(),
                                           SQLITE_TRANSIENT)) {
                throw ErrBase("sqlite3_bind_text(2)");
        }
        if (SQLITE_OK != sqlite3_bind_text(stmt,3,
                                           owner.c_str(),owner.size(),
                                           SQLITE_TRANSIENT)) {
                throw ErrBase("sqlite3_bind_text(3)");
        }
        if (SQLITE_OK != sqlite3_bind_text(stmt,4,
                                           data.c_str(),data.size(),
                                           SQLITE_TRANSIENT)) {
                throw ErrBase("sqlite3_bind_text(4)");
        }
        if (SQLITE_DONE != sqlite3_step(stmt)) {
                throw ErrBase("sqlite3_step()");
        }
}

/**
 *
 */
void
dbStore(const std::string &display, const std::string &outputFile)
{
        sqlite3 *db;
        if (SQLITE_OK != sqlite3_open(outputFile.c_str(), &db)) {
                throw ErrBase("sqlite3_open()");
        }

        sqlite3_stmt *stmt;
        if (SQLITE_OK != sqlite3_prepare_v2(db,
                                            "INSERT INTO clipboard"
                                            " (ts,name,owner,data)"
                                            " VALUES(?,?,?,?)",
                                            -1,
                                            &stmt,
                                            NULL)) {
                throw ErrBase("sqlite3_prepare_v2()");
        }
        ClipSniff cs(display);
        std::pair<std::string,std::string> lastData;
        for(;;) {
                std::pair<std::string,std::string> data, owners;
                data = cs.get();
                if (data == lastData) {
                        sleep(1);
                        continue;
                }

                owners = cs.getOwners();
                if (data.first != lastData.first) {
                        saveDb("PRIMARY", data.first, owners.first, stmt);
                }
                if (data.second != lastData.second) {
                        saveDb("CLIPBOARD", data.second, owners.second, stmt);
                }
                

                lastData = data;
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
}
END_NAMESPACE();

/**
 *
 */
int
main(int argc, char**argv)
{
        printf("ClipSniff %s\n", PACKAGE_VERSION);
        argv0 = argv[0];
        std::string outputFile, display;

        { /* handle GNU options */
                int c;
                for (c = 1; c < argc; c++) {
                        if (!strcmp(argv[c], "--")) {
                                break;
                        } else if (!strcmp(argv[c], "--help")) {
                                usage(EXIT_SUCCESS);
                        } else if (!strcmp(argv[c], "--version")) {
                                printVersion();
                        }
                }
        }

        // option parsing
        int opt;
        while ((opt = getopt(argc, argv, "hd:Vw:")) != -1) {
                switch (opt) {
                case 'h':
                        usage(EXIT_SUCCESS);
                        break;
                case 'w':
                        outputFile = optarg;
                        break;
                case 'V':
                        printVersion();
                        break;
                case 'd':
                        display = optarg;
                        break;
                default: /* '?' */
                        usage(EXIT_FAILURE);
                }
        }

        try {
                if (outputFile.empty()) {
                        ClipSniff cs(display);
                        std::pair<std::string, std::string> c;
                        c = cs.get();
                        std::cout << "Primary owner:   "
                                  << cs.getOwner() << std::endl
                                  << "Data:            "
                                  << c.first << std::endl
                                  << "Clipboard owner: "
                                  << cs.getOwner("CLIPBOARD") << std::endl
                                  << "Data:            "
                                  << c.second << std::endl;
                } else {
                        dbStore(display, outputFile);
                }
        } catch (const std::exception &e) {
                std::cerr << argv0 << ": fatal exception: "
                          << e.what() << std::endl;
        }
}
