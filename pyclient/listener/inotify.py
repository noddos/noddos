import collections
from ctypes import *

# bit masks
IN_ISDIR      = 0x40000000
IN_ALL_EVENTS = 0xfff

# from /usr/src/linux/include/linux/inotify.h

IN_ACCESS =         0x00000001     # File was accessed
IN_MODIFY =         0x00000002     # File was modified
IN_ATTRIB =         0x00000004     # Metadata changed
IN_CLOSE_WRITE =    0x00000008     # Writtable file was closed
IN_CLOSE_NOWRITE =  0x00000010     # Unwrittable file closed
IN_OPEN =           0x00000020     # File was opened
IN_MOVED_FROM =     0x00000040     # File was moved from X
IN_MOVED_TO =       0x00000080     # File was moved to Y
IN_CREATE =         0x00000100     # Subfile was created
IN_DELETE =         0x00000200     # Subfile was delete
IN_DELETE_SELF =    0x00000400     # Self was deleted
IN_MOVE_SELF =      0x00000800     # Self was moved
IN_UNMOUNT =        0x00002000     # Backing fs was unmounted
IN_Q_OVERFLOW =     0x00004000     # Event queued overflowed
IN_IGNORED =        0x00008000     # File was ignored

IN_ONLYDIR =         0x01000000      # only watch the path if it is a directory
IN_DONT_FOLLOW =     0x02000000      # don't follow a sym link
IN_MASK_ADD =        0x20000000      # add to the mask of an already existing watch
IN_ISDIR =           0x40000000      # event occurred against dir
IN_ONESHOT =         0x80000000      # only send event once

IN_CLOSE =      IN_CLOSE_WRITE | IN_CLOSE_NOWRITE   # closes
IN_MOVED =      IN_MOVED_FROM | IN_MOVED_TO         # moves
IN_CHANGED =    IN_MODIFY | IN_ATTRIB               # changes

IN_WATCH_MASK = IN_MODIFY | IN_ATTRIB | \
                IN_CREATE | IN_DELETE | \
                IN_DELETE_SELF | IN_MOVE_SELF | \
                IN_UNMOUNT | IN_MOVED_FROM | IN_MOVED_TO


_flag_to_human = {
    IN_ACCESS: 'access',
    IN_MODIFY: 'modify',
    IN_ATTRIB: 'attrib',
    IN_CLOSE_WRITE: 'close_write',
    IN_CLOSE_NOWRITE: 'close_nowrite',
    IN_OPEN: 'open',
    IN_MOVED_FROM: 'moved_from',
    IN_MOVED_TO: 'moved_to',
    IN_CREATE: 'create',
    IN_DELETE: 'delete',
    IN_DELETE_SELF: 'delete_self',
    IN_MOVE_SELF: 'move_self',
    IN_UNMOUNT: 'unmount',
    IN_Q_OVERFLOW: 'queue_overflow',
    IN_IGNORED: 'ignored',
    IN_ONLYDIR: 'only_dir',
    IN_DONT_FOLLOW: 'dont_follow',
    IN_MASK_ADD: 'mask_add',
    IN_ISDIR: 'is_dir',
    IN_ONESHOT: 'one_shot'}


class inotify_event_struct(Structure):
    """
    Structure representation of the inotify_event structure
    (used in buffer size calculations)::
        struct inotify_event {
            __s32 wd;            /* watch descriptor */
            __u32 mask;          /* watch mask */
            __u32 cookie;        /* cookie to synchronize two events */
            __u32 len;           /* length (including nulls) of name */
            char  name[0];       /* stub for possible name */
        };
    """
    _fields_ = [('wd', c_int),
                ('mask', c_uint32),
                ('cookie', c_uint32),
                ('len', c_uint32),
                ('name', c_char_p)]

InotifyEvent = collections.namedtuple('InotifyEvent', ['wd', 'mask', 'cookie', 'len', 'name'])

EVENT_SIZE = sizeof(inotify_event_struct)
EVENT_BUFFER_SIZE = 1024 * (EVENT_SIZE + 16)

# wrap for inotify system call
try:
    cdll.LoadLibrary("libc.so.6")  
    libc = CDLL("libc.so.6")   
except:
    # On OpenWRT, we don't have libc, we have ulibc
    cdll.LoadLibrary("libc.so.0")  
    libc = CDLL("libc.so.0")   

libc.inotify_init.argtypes = []
libc.inotify_init.restype = c_int
#libc.inotify_add_watch.argtypes = [c_int, c_wchar_p, c_uint32]
libc.inotify_add_watch.argtypes = [c_int, c_char_p, c_uint32]
libc.inotify_add_watch.restype = c_int
libc.inotify_rm_watch.argtypes = [c_int, c_int]
libc.inotify_rm_watch.restype = c_int

inotify_init = libc.inotify_init
inotify_add_watch = libc.inotify_add_watch
inotify_rm_watch = libc.inotify_rm_watch
