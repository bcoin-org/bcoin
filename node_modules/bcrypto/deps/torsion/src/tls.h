/*!
 * tls.h - thread-local storage for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

#ifndef _TORSION_TLS_H
#define _TORSION_TLS_H

/* TLS Compiler Support
 *
 * GCC:
 *
 * - Supports TLS via __thread[1].
 * - TLS first implemented in GCC 3.3[1].
 * - TLS emulation added in GCC 4.3[2].
 *
 * Clang:
 *
 * - Supports TLS via __thread, __declspec(thread)[3].
 * - TLS first implemented in Clang 2.0[4].
 * - TLS emulation added in Clang 3.8[5].
 * - TLS "modernized" in Clang 2.6[6].
 * - Support for Mac OSX added in Clang 2.8[7].
 * - Support for Mac OSX "modernized" in Clang 3.0[8].
 * - Support for System Z added in Clang 3.3[9].
 * - Support for __has_extension(c_thread_local) added in 3.4[10].
 * - Support for x86 Windows added in Clang 3.5[11].
 * - Support for x86-64 Windows added in Clang 3.5[12].
 * - Support for x86 Cygwin added in Clang 3.8[13].
 * - Support for Apple iOS added in Clang 3.8[14].
 * - Support for ARM Windows added in Clang 3.9[15].
 * - Support for OpenBSD added in Clang 5.0[16].
 * - Support for iOS Simulator added in Clang 7.0[17].
 * - Support for RISC-V added in Clang 9.0[18].
 * - No support for x86-64 Cygwin as of Clang 10.0[19].
 * - No support for ARM Cygwin as of Clang 10.0[20].
 * - No support for Haiku as of Clang 10.0[21].
 *
 * Intel C:
 *
 * - Supports TLS via __thread[22], __declspec(thread)[23].
 * - Intel mentions __thread in documentation from 2004[22].
 *   This would suggest support from version 8.x onward.
 * - Furthermore, this post[24] suggests __thread existed
 *   at least as far back as 2006 (version 9.0 or 10.0).
 * - Apple and Mach-O support implemented in 15.0[25].
 *
 * MSVC:
 *
 * - Supports TLS via __declspec(thread)[26].
 * - Unknown when TLS was implemented, but this repo[27]
 *   from 2009 suggests it existed in VS .NET 2002 (7.0).
 * - Another project dating from 1996-2003 suggests
 *   TLS was supported in Visual Studio 6.0 (1998)[28].
 * - Usage of TLS appears on the MSDN Library CD for
 *   Visual Studio 6.0 (1998). The author of the code
 *   samples claims to have written them in 1995. This
 *   means TLS would have been supported in MSVC 4.0.
 *
 * Sun Pro C / Sun Studio / Solaris Studio:
 *
 * - Supports TLS via __thread[29].
 * - First mentioned in documentation for Sun Studio 12[30].
 *   This would suggest support from 5.9 onward.
 *
 * IBM XL C:
 *
 * - Supports TLS via __thread[31].
 * - Support added for Linux in XL C 8.0[32].
 * - Support added for AIX in XL C 10.1[32].
 * - Note that -qtls must be passed on the command line.
 *
 * C++ Builder:
 *
 * - Supports TLS via __thread[33], __declspec(thread)[34].
 * - Mentioned in C++ Builder 2009 documentation[33].
 *
 * Digital Mars C/C++:
 *
 * - Supports TLS via __declspec(thread) (32 bit only)[35].
 * - TLS supported since at least 2001 (8.22)[36].
 *
 * ARM CC:
 *
 * - Supports TLS via __thread, __declspec(thread)[37][38].
 * - Mentioned on the gnulib mailing list[39].
 *
 * HP ANSI C:
 *
 * - Supports TLS via __thread[40].
 * - The release notes suggest this has been the
 *   case since at least version A.05.55.02.
 *
 * Watcom C:
 *
 * - TLS supported via __declspec(thread)[41].
 * - TLS supported since at least version 11.0c[41].
 *   Notable as this predates Open Watcom.
 *
 * Wind River Compiler (Diab C):
 *
 * - TLS supported via __thread[42][43].
 * - TLS supported since at least 2007 (5.6)[43].
 *
 * NWCC:
 *
 * - TLS supported via __thread[44].
 * - TLS first implemented in NWCC 0.7.5 (2008).
 *   See develop/oldnews/NEWS-0.7.5.
 *
 * Metrowerks C:
 *
 * - TLS supported via __declspec(thread)[45].
 *   Documentation explicitly states this is
 *   windows-only.
 * - TLS supported since at least Dec. 1996[45].
 *   This places the support timeframe somewhere
 *   around CodeWarrior 10 or 11 (not CW Pro).
 * - Google states that the PDF is from Oct 1995,
 *   which would place the timeframe more near
 *   CodeWarrior 7 (again, _not_ CW Pro).
 * - Notable as this is the earliest TLS support
 *   mentioned by this document.
 * - The QuickTime header files suggest that
 *   `__declspec` itself was only usable after
 *   CodeWarrior Pro 2 (1997) was released[46].
 *
 * CompCert:
 *
 * - TLS not yet supported[47].
 *
 * Portable C Compiler:
 *
 * - TLS supported via __thread and #pragma tls[48].
 * - TLS first implemented in 1.0.0[49][50].
 *
 * C11:
 *
 * - C11 specifies support for _Thread_local[51].
 * - Support can be tested by checking both:
 *
 *     __STDC_VERSION__ >= 201112L
 *     !defined(__STDC_NO_THREADS__)
 *
 *   However, some compilers do not define STDC_NO_THREADS
 *   or do not define it directly (in particular, Intel C
 *   versions less than 18.0.0[52]).
 *
 * [1] https://gcc.gnu.org/onlinedocs/gcc-3.3.1/gcc/Thread-Local.html
 * [2] https://github.com/gcc-mirror/gcc/commit/8893239dc4ed32bd3bb4e00d6e43b859554ab82a
 * [3] https://clang.llvm.org/docs/AttributeReference.html#thread
 * [4] https://releases.llvm.org/2.0/docs/ReleaseNotes.html
 * [5] https://releases.llvm.org/3.8.0/docs/ReleaseNotes.html
 * [6] https://github.com/llvm/llvm-project/blob/llvmorg-2.6.0/clang/lib/Basic/Targets.cpp
 * [7] https://github.com/llvm/llvm-project/blob/llvmorg-2.8.0/clang/lib/Basic/Targets.cpp#L153
 * [8] https://github.com/llvm/llvm-project/blob/llvmorg-3.0.0/clang/lib/Basic/Targets.cpp#L202
 * [9] https://github.com/llvm/llvm-project/blob/llvmorg-3.3.0/clang/lib/Basic/Targets.cpp#L4352
 * [10] https://github.com/llvm/llvm-project/blob/llvmorg-3.4.0/clang/lib/Lex/PPMacroExpansion.cpp#L998
 * [11] https://github.com/llvm/llvm-project/blob/llvmorg-3.5.0/clang/lib/Basic/Targets.cpp#L3110
 * [12] https://github.com/llvm/llvm-project/blob/llvmorg-3.8.0/clang/lib/Basic/Targets.cpp#L4133
 * [13] https://github.com/llvm/llvm-project/blob/llvmorg-3.8.0/clang/lib/Basic/Targets.cpp#L3855
 * [14] https://github.com/llvm/llvm-project/blob/llvmorg-3.8.0/clang/lib/Basic/Targets.cpp#L232
 * [15] https://github.com/llvm/llvm-project/blob/llvmorg-3.9.0/clang/lib/Basic/Targets.cpp#L5495
 * [16] https://github.com/llvm/llvm-project/blob/llvmorg-5.0.0/clang/lib/Basic/Targets.cpp#L555
 * [17] https://github.com/llvm/llvm-project/blob/llvmorg-7.0.0/clang/lib/Basic/Targets/OSTargets.h#L103
 * [18] https://github.com/llvm/llvm-project/blob/llvmorg-9.0.0/clang/lib/Basic/Targets/RISCV.h#L24
 * [19] https://github.com/llvm/llvm-project/blob/llvmorg-10.0.0/clang/lib/Basic/Targets/X86.h#L819
 * [20] https://github.com/llvm/llvm-project/blob/llvmorg-10.0.0/clang/lib/Basic/Targets/ARM.cpp#L1208
 * [21] https://github.com/llvm/llvm-project/blob/llvmorg-10.0.0/clang/lib/Basic/Targets/OSTargets.h#L310
 * [22] https://software.intel.com/sites/default/files/ae/4f/6320
 * [23] https://community.intel.com/t5/Intel-C-Compiler/Thread-local-storage-support-on-Windows/td-p/949321
 * [24] https://community.intel.com/t5/Intel-C-Compiler/thread-local-storage-linking-problems/td-p/932631
 * [25] https://community.intel.com/t5/Intel-C-Compiler/Mach-O-thread-local-storage/td-p/948267
 * [26] https://docs.microsoft.com/en-us/cpp/c-language/thread-local-storage
 * [27] https://github.com/snaewe/loki-lib/commit/7d8e59abc8f48785d564ddabab5ba3f01cd24444
 * [28] http://www.simkin.co.uk/Docs/cpp/api/skGeneral_8h-source.html
 * [29] https://docs.oracle.com/cd/E18659_01/html/821-1383/bkaeg.html
 * [30] https://docs.oracle.com/cd/E19205-01/819-5267/bkaeg/index.html
 * [31] https://www.ibm.com/support/knowledgecenter/en/SSXVZZ_13.1.3/com.ibm.xlcpp1313.lelinux.doc/language_ref/thread.html
 * [32] https://www.ibm.com/support/pages/node/318521#6
 * [33] http://docs.embarcadero.com/products/rad_studio/delphiAndcpp2009/HelpUpdate2/EN/html/devwin32/threadsusingthreadlocalvariables_xml.html
 * [34] http://docwiki.embarcadero.com/RADStudio/Sydney/en/Declspec(thread)
 * [35] https://web.archive.org/web/20010222185824/https://www.digitalmars.com/ctg/ctgLanguageImplementation.html
 * [36] https://digitalmars.com/changelog.html#new822
 * [37] https://developer.arm.com/docs/dui0472/latest/compiler-specific-features/__declspecthread
 * [38] https://developer.arm.com/docs/dui0491/g/compiler-specific-features/__declspec-attributes
 * [39] https://lists.gnu.org/archive/html/bug-gnulib/2019-06/msg00063.html
 * [40] http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.172.9698&rep=rep1&type=pdf
 * [41] http://www.os2site.com/sw/dev/watcom/11.0c/c_readme.txt
 * [42] https://community.synopsys.com/s/article/Multiple-parse-warnings-for-defined-variables
 * [43] http://read.pudn.com/downloads259/doc/1193608/wr_compiler_error_messages_reference_5.6.pdf
 * [44] http://nwcc.sourceforge.net/features.html
 * [45] http://index-of.co.uk/C++/CodeWarrior%20C%20and%20C++%20and%20Assembly%20Language%20Reference.pdf
 * [46] https://github.com/OPK/xpwn/blob/master/idevice/QuicktimeSDK/CIncludes/ConditionalMacros.h
 * [47] https://github.com/AbsInt/CompCert/issues/268
 * [48] https://github.com/IanHarvey/pcc/blob/master/cc/ccom/gcc_compat.c#L261
 * [49] https://github.com/IanHarvey/pcc/commit/e2ad48a
 * [50] https://github.com/IanHarvey/pcc/commit/109a8ee
 * [51] https://en.cppreference.com/w/c/keyword/_Thread_local
 * [52] https://software.intel.com/en-us/forums/intel-c-compiler/topic/721059
 */

/* Apple Quirks
 *
 * The TLS situation on Apple is mind-bogglingly stupid.
 * This results from the fact that the Mach-O executable
 * format is inferior to both ELF and PE, and also sheer
 * incompetence on Apple's part in altering Clang features
 * and intentially disabling TLS when it was supported.
 *
 * Note that as we go through the explanation below, we
 * have to distinguish Apple Clang from Real Clang.
 *
 * The Facts:
 *
 *   - Apple enabled TLS in Xcode 8.0[1] (Real Clang 3.9.0[2]).
 *   - Intel enabled TLS in ICC 15.0.0[3].
 *   - Real Clang 3.0 only supported OSX TLS[4].
 *   - Real Clang 3.8 added support for iOS TLS[5].
 *   - Real Clang 7.0 added support for iOS Simulator TLS[6].
 *   - Apple Clang 5.0 (Xcode 5.0.0) included Real Clang 3.3[2] (no TLS[1]).
 *   - Apple Clang 8.0.0 (Xcode 8.0) included Real Clang 3.9.0[1][2].
 *   - Apple Clang 10.0.1 (Xcode 10.2) included Real Clang 7.0.0[2].
 *   - The minimum OSX version required must be >=10.7 for TLS[6].
 *   - The minimum iOS 64-bit version required must be >=8 for TLS[6].
 *   - The minimum iOS 32-bit version required must be >=9 for TLS[6].
 *   - The minimum iOS simulator version required must be >=10 for TLS[6].
 *   - The iOS requirements also apply to tvOS[6].
 *   - The minimum watchOS version required must be >=2 for TLS[6].
 *   - The minimum watchOS simulator version required must be >=3 for TLS[6].
 *   - Apple Clang's changes affect __has_extension(c_thread_local)[7].
 *
 * [1] https://stackoverflow.com/a/29929949
 * [2] https://en.wikipedia.org/wiki/Xcode#Xcode_7.0_-_11.x_(since_Free_On-Device_Development)
 * [3] https://community.intel.com/t5/Intel-C-Compiler/Mach-O-thread-local-storage/td-p/948267
 * [4] https://github.com/llvm/llvm-project/blob/llvmorg-3.0.0/clang/lib/Basic/Targets.cpp#L202
 * [5] https://github.com/llvm/llvm-project/blob/llvmorg-3.8.0/clang/lib/Basic/Targets.cpp#L232
 * [6] https://github.com/llvm/llvm-project/blob/llvmorg-7.0.0/clang/lib/Basic/Targets/OSTargets.h#L103
 * [7] https://stackoverflow.com/a/23850891
 */

/* Android Quirks
 *
 * Android apparently has issues compiling with NDK < r12[1].
 * According to SO, this appears to be fixed with NDK r12[2],
 * which upgrades Clang to 3.8[3][4].
 *
 * Note that the Android NDK does not provide a #define for
 * us to check[5]. We could check the Clang version, but NDK
 * r11 _also_ used Clang 3.8[6]. Instead, we must check for
 * NDK r15, which was upgraded to Clang 5.0[7].
 *
 * As of Android NDK r16, __NDK_MAJOR__ does indeed exist[8],
 * but this is not suitable for our purposes.
 *
 * [1] https://stackoverflow.com/questions/27191214
 * [2] https://stackoverflow.com/a/27195324
 * [3] https://developer.android.com/ndk/downloads/revision_history
 * [4] https://github.com/android/ndk/blob/master/Changelogs/Changelog-r12.md#clang
 * [5] https://github.com/android/ndk/issues/407
 * [6] https://github.com/android/ndk/blob/master/Changelogs/Changelog-r11.md#clang
 * [7] https://github.com/android/ndk/blob/master/Changelogs/Changelog-r15.md#clang
 * [8] https://groups.google.com/forum/?_escaped_fragment_=topic/android-ndk/cf9_f1SLXls
 */

#ifndef TORSION_HAVE_CONFIG

#if defined(__has_extension)
#  define TORSION__HAS_EXTENSION __has_extension
#else
#  define TORSION__HAS_EXTENSION(x) 0
#endif

/* Detect Apple version. */
#if defined(__APPLE__) && defined(__MACH__)
/* Some hackery to get Apple versions: Compilers with
 * Darwin targets pass in these defines as they are
 * necessary for Apple's Availability.h. We can abuse
 * this fact to avoid including the header (which may
 * not be available on older Apple versions).
 *
 * OSX versions prior to 10.10 are formatted as VVRP.
 * Everything else is formatted as VVRRPP.
 */
#  if defined(__APPLE_EMBEDDED_SIMULATOR__)
#    define TORSION__IOS_VERSION 100000 /* 10.0 (2016) */
#  elif defined(__x86_64__) || defined(__aarch64__)
#    define TORSION__IOS_VERSION 80000 /* 8.0 (2014) */
#  else
#    define TORSION__IOS_VERSION 90000 /* 9.0 (2015) */
#  endif
#  if defined(__APPLE_EMBEDDED_SIMULATOR__)
#    define TORSION__WOS_VERSION 30000 /* 3.0 (2016) */
#  else
#    define TORSION__WOS_VERSION 20000 /* 2.0 (2015) */
#  endif
#  if defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__)
#    if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 1070 /* 10.7 (2011) */
#      define TORSION__APPLE_OS
#    endif
#  elif defined(__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__)
#    if __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ >= TORSION__IOS_VERSION
#      define TORSION__APPLE_OS
#    endif
#  elif defined(__ENVIRONMENT_TV_OS_VERSION_MIN_REQUIRED__)
#    if __ENVIRONMENT_TV_OS_VERSION_MIN_REQUIRED__ >= TORSION__IOS_VERSION
#      define TORSION__APPLE_OS
#    endif
#  elif defined(__ENVIRONMENT_WATCH_OS_VERSION_MIN_REQUIRED__)
#    if __ENVIRONMENT_WATCH_OS_VERSION_MIN_REQUIRED__ >= TORSION__WOS_VERSION
#      define TORSION__APPLE_OS
#    endif
#  endif
#endif

/* Detect TLS support. */
#if defined(__DMC__)
#  if defined(_M_IX86) && __DMC__ >= 0x822 /* 8.22 (2001) */
#    define TORSION_TLS_MSVC
#  endif
#elif defined(__HP_cc)
#  if __HP_cc >= 55502 /* A.05.55.02 (2004) */
#    define TORSION_TLS_GNUC
#  endif
#  define TORSION_TLS_GNUC
#elif defined(__WATCOMC__)
#  if __WATCOMC__ >= 1200 /* Open Watcom 1.0 (2003) */
#    define TORSION_TLS_MSVC
#  endif
#elif defined(__DCC__)
#  if defined(__VERSION_NUMBER__) && __VERSION_NUMBER__ >= 5600 /* 5.6 (2007) */
#    define TORSION_TLS_GNUC
#  endif
#elif defined(__PCC__)
#  if __PCC__ >= 1 /* 1.0.0 (2011) */
#    define TORSION_TLS_GNUC
#  endif
#elif defined(__NWCC__)
#  define TORSION_TLS_GNUC /* 0.7.5 (2008) */
#elif defined(__MWERKS__)
#  if defined(__INTEL__) && __INTEL__ && __MWERKS__ >= 0x2000 /* CW Pro 2 (1997) */
#    define TORSION_TLS_MSVC
#  endif
#elif defined(__SUNPRO_C)
#  if __SUNPRO_C >= 0x590 /* 5.9 (2007) */
#    define TORSION_TLS_GNUC
#  endif
#elif defined(__INTEL_COMPILER)
#  if defined(__APPLE__) && defined(__MACH__)
#    if defined(TORSION__APPLE_OS) && __INTEL_COMPILER >= 1500 /* 15.0.0 (2014) */
#      define TORSION_TLS_GNUC
#    endif
#  elif __INTEL_COMPILER >= 800 /* 8.0.0 (2003) */
#    define TORSION_TLS_BOTH
#  endif
#elif defined(__ICC)
#  if !defined(__APPLE__) && __ICC >= 800 /* 8.0.0 (2003) */
#    define TORSION_TLS_GNUC
#  endif
#elif defined(__ICL)
#  if __ICL >= 800 /* 8.0.0 (2003) */
#    define TORSION_TLS_MSVC
#  endif
#elif defined(__clang__)
#  if defined(__apple_build_version__)
#    if defined(TORSION__APPLE_OS) && __apple_build_version__ >= 8000038 /* 800.0.38 (2016) */
#      define TORSION_TLS_GNUC
#    endif
#  elif TORSION__HAS_EXTENSION(c_thread_local) /* 3.4 (late 2013) */
#    if defined(__ANDROID__)
#      if defined(__clang_major__) && __clang_major__ >= 5 /* 5.0 (2017) */
#        define TORSION_TLS_GNUC
#      endif
#    else
#      define TORSION_TLS_BOTH
#    endif
#  endif
#elif defined(__xlC__)
/* Newer XL C versions are based on clang and should be caught above. */
#  if defined(__linux__)
#    if __xlC__ >= 0x0800 /* 8.0.0 (unknown) */
#      define TORSION_TLS_GNUC
#    endif
#  else /* _AIX */
#    if __xlC__ >= 0x0A01 /* 10.1.0 (2008) */
#      define TORSION_TLS_GNUC
#    endif
#  endif
#elif defined(__CC_ARM)
/* Newer ARM CC versions are based on clang and should be caught above. */
#  if defined(__ARMCC_VERSION) && __ARMCC_VERSION >= 510000 /* 5.1 (2011) */
#    define TORSION_TLS_BOTH
#  endif
#elif defined(__BORLANDC__)
/* Newer C++ Builder versions are based on clang and should be caught above. */
#  if __BORLANDC__ >= 0x613 /* C++ Builder 2009 */
#    define TORSION_TLS_BOTH
#  endif
#elif defined(_MSC_VER)
#  if _MSC_VER >= 1200 /* Visual Studio 6.0 (1998) */
#    define TORSION_TLS_MSVC
#  endif
#elif defined(__GNUC__) && defined(__GNUC_MINOR__)
#  if defined(__ELF__) && (defined(__alpha__) || defined(__i386__)  \
                        || defined(__x86_64__) || defined(__ia64__) \
                        || defined(__s390__) || defined(__s390x__))
#    if ((__GNUC__ << 16) + __GNUC_MINOR__ >= 0x30003) /* 3.3 (2003) */
#      define TORSION_TLS_GNUC
#    endif
#  else
#    if ((__GNUC__ << 16) + __GNUC_MINOR__ >= 0x40003) /* 4.3 (2008) */
#      define TORSION_TLS_GNUC
#    endif
#  endif
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  include <limits.h> /* <stdc-predef.h> */
#  ifndef __STDC_NO_THREADS__
#    define TORSION_TLS_STDC
#  endif
#endif

#ifdef TORSION_TLS_BOTH
#  if defined(_WIN32) && !defined(__MINGW32__)
#    define TORSION_TLS_MSVC
#  else
#    define TORSION_TLS_GNUC
#  endif
#endif

/* Pick thread-local keyword. */
#if defined(TORSION_TLS_MSVC)
#  define TORSION_HAVE_TLS
#  define TORSION_TLS __declspec(thread)
#elif defined(TORSION_TLS_GNUC)
#  define TORSION_HAVE_TLS
#  define TORSION_TLS __thread
#elif defined(TORSION_TLS_STDC)
#  define TORSION_HAVE_TLS
#  define TORSION_TLS _Thread_local
#else
#  define TORSION_TLS
#endif

/* Fall back to pthread if available. */
#if defined(TORSION_HAVE_PTHREAD)
/* Already have pthread. */
#elif defined(__APPLE__) && defined(__MACH__)
/* Apple binaries link to libSystem (which exposes pthread). */
#  include <AvailabilityMacros.h>
#  if MAC_OS_X_VERSION_MAX_ALLOWED >= 1040 /* 10.4 (2005) */
#    define TORSION_HAVE_PTHREAD
#  endif
#elif defined(__ANDROID__)
/* Bionic has builtin pthread support. */
#  include <sys/types.h> /* <sys/cdefs.h> */
#  ifdef __BIONIC__
#    define TORSION_HAVE_PTHREAD
#  endif
#endif

/* Allow overrides (for testing). */
#ifdef TORSION_NO_TLS
#  undef TORSION_HAVE_TLS
#  undef TORSION_TLS
#  define TORSION_TLS
#endif

#ifdef TORSION_NO_PTHREAD
#  undef TORSION_HAVE_PTHREAD
#endif

#endif /* !TORSION_HAVE_CONFIG */

#endif /* _TORSION_TLS_H */
