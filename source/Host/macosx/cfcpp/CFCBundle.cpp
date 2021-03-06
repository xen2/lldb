//===-- CFCBundle.cpp -------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "CFCBundle.h"
#include "CFCString.h"

//----------------------------------------------------------------------
// CFCBundle constructor
//----------------------------------------------------------------------
CFCBundle::CFCBundle(const char *path) :
    CFCReleaser<CFBundleRef>()
{
    if (path && path[0])
        SetPath(path);
}

CFCBundle::CFCBundle(CFURLRef url) :
    CFCReleaser<CFBundleRef>(url ? CFBundleCreate(NULL, url) : NULL)
{
}

//----------------------------------------------------------------------
// Destructor
//----------------------------------------------------------------------
CFCBundle::~CFCBundle()
{
}

//----------------------------------------------------------------------
// Set the path for a bundle by supplying a
//----------------------------------------------------------------------
bool
CFCBundle::SetPath (const char *path)
{
    CFAllocatorRef alloc = kCFAllocatorDefault;
    // Release our old bundle and URL
    reset();

    // Make a CFStringRef from the supplied path
    CFCString cf_path;
    cf_path.SetFileSystemRepresentation(path);
    if (cf_path.get())
    {
        // Make our Bundle URL
        CFCReleaser<CFURLRef> bundle_url (::CFURLCreateWithFileSystemPath (alloc, cf_path.get(), kCFURLPOSIXPathStyle, true));
        if (bundle_url.get())
            reset (::CFBundleCreate (alloc, bundle_url.get()));
    }
    return get() != NULL;
}

bool
CFCBundle::GetPath (char *dst, size_t dst_len)
{
    CFBundleRef bundle = get();
    if (bundle)
    {
        CFCReleaser<CFURLRef> bundle_url (CFBundleCopyBundleURL (bundle));
        if (bundle_url.get())
        {
            Boolean resolveAgainstBase = 0;
            return ::CFURLGetFileSystemRepresentation (bundle_url.get(), resolveAgainstBase, (UInt8 *)dst, dst_len) != 0;
        }
    }
    return false;
}   

CFStringRef
CFCBundle::GetIdentifier () const
{
    CFBundleRef bundle = get();
    if (bundle != NULL)
        return ::CFBundleGetIdentifier (bundle);
    return NULL;
}

CFTypeRef
CFCBundle::GetValueForInfoDictionaryKey(CFStringRef key) const
{
    CFBundleRef bundle = get();
    if (bundle != NULL)
        return ::CFBundleGetValueForInfoDictionaryKey(bundle, key);
    return NULL;
}

CFURLRef
CFCBundle::CopyExecutableURL () const
{
    CFBundleRef bundle = get();
    if (bundle != NULL)
        return CFBundleCopyExecutableURL(bundle);
    return NULL;
}
