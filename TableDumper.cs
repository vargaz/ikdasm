//
// Copyright (C) 2011 Xamarin Inc (http://www.xamarin.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using IKVM.Reflection;

namespace Ildasm
{
	enum MetadataTableIndex {
		Assembly = 0x20,
	}

	class TableDumper
	{
		Universe universe;
		Assembly assembly;
		Module module;

		public TableDumper (string inputFile) {
            universe = new Universe (UniverseOptions.None);

            var raw = universe.OpenRawModule (System.IO.File.OpenRead (inputFile), System.IO.Path.GetTempPath () + "/Dummy");
            if (raw.IsManifestModule)
            {
                assembly = universe.LoadAssembly (raw);
                module = assembly.ManifestModule;
            }
            else
            {
                var ab = universe.DefineDynamicAssembly (new AssemblyName ("<ModuleContainer>"), IKVM.Reflection.Emit.AssemblyBuilderAccess.ReflectionOnly);
                assembly = ab;
                module = ab.__AddModule (raw);
            }			
		}

		public void DumpTable (TextWriter w, MetadataTableIndex tableIndex) {
			switch (tableIndex) {
			case MetadataTableIndex.Assembly:
				DumpAssemblyTable (w);
				break;
			default:
				throw new NotImplementedException ();
			}
		}

		void HexDump (TextWriter w, byte[] bytes, int len) {
			for (int i = 0; i < len; ++i) {
				if ((i % 16) == 0)
					w.Write (String.Format ("\n0x{0:x08}: ", i));
				w.Write (String.Format ("{0:x02} ", bytes [i]));
			}
		}

		void DumpAssemblyTable (TextWriter w) {
			var t = module.AssemblyTable;
			w.WriteLine ("Assembly Table");
			foreach (var r in t.records) {
				w.WriteLine (String.Format ("Name:          {0}", module.GetString (r.Name)));
				w.WriteLine (String.Format ("Hash Algoritm: 0x{0:x08}", r.HashAlgId));
				w.WriteLine (String.Format ("Version:       {0}.{1}.{2}.{3}", r.MajorVersion, r.MinorVersion, r.BuildNumber, r.RevisionNumber));
				w.WriteLine (String.Format ("Flags:         0x{0:x08}", r.Flags));
				w.WriteLine (String.Format ("PublicKey:     BlobPtr (0x{0:x08})", r.PublicKey));

				var blob = module.GetBlob (r.PublicKey);
				if (blob.Length == 0) {
					w.WriteLine ("\tZero sized public key");
				} else {
					w.Write ("\tDump:");
					byte[] bytes = blob.ReadBytes (blob.Length);
					HexDump (w, bytes, bytes.Length);
					w.WriteLine ();
				}
				w.WriteLine (String.Format ("Culture:       {0}", module.GetString (r.Culture)));
				w.WriteLine ();
			}
		}
	}
}
