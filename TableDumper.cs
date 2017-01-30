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
		Module = 0x0,
		TypeRef = 0x1,
		TypeDef = 0x2,
		FieldPtr = 0x3,
		Field = 0x4,
		MethodPtr = 0x5,
		Method = 0x6,
		ParamPtr = 0x7,
		Param = 0x8,
		InterfaceImpl = 0x9,
		MemberRef = 0xa,
		Constant = 0xb,
		CustomAttr = 0xc,
		FieldMarshal = 0xd,
		DeclSecurity = 0xe,
		ClassLayout = 0xf,
		FieldLayout = 0x10,
		StandaloneSig = 0x11,
		EventMap = 0x12,
		EventPtr = 0x13,
		Event = 0x14,
		PropertyMap = 0x15,
		PropertyPtr = 0x16,
		Property = 0x17,
		MethodSem = 0x18,
		MethodImpl = 0x19,
		ModuleRef = 0x1a,
		TypeSpec = 0x1b,
		ImplMap = 0x1c,
		FieldRVA = 0x1d,
		EncLog = 0x1e,
		EncMap = 0x1f,
		Assembly = 0x20,
		AssemblyRef = 0x23,
	}

	class TableDumper
	{
		Universe universe;
		Assembly assembly;
		Module module;

		public TableDumper (string inputFile, string deltaFile, string deltaILFile) {
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

			if (deltaFile != null) {
				var fs = File.OpenRead (deltaFile);
				var ilfs = File.OpenRead (deltaILFile);
				assembly.AddDelta (fs, ilfs);
			}
		}

		public void DumpTable (TextWriter w, MetadataTableIndex tableIndex) {
			switch (tableIndex) {
			case MetadataTableIndex.Assembly:
				DumpAssemblyTable (w);
				break;
			case MetadataTableIndex.AssemblyRef:
				DumpAssemblyRefTable (w);
				break;
			case MetadataTableIndex.ModuleRef:
				DumpModuleRefTable (w);
				break;
			case MetadataTableIndex.EncLog:
				DumpEncLogTable (w);
				break;
			case MetadataTableIndex.EncMap:
				DumpEncMapTable (w);
				break;
			case MetadataTableIndex.Module:
				DumpModuleTable (w);
				break;
			default:
				throw new NotImplementedException ();
			}
		}

		void HexDump (TextWriter w, byte[] bytes, int len) {
			for (int i = 0; i < len; ++i) {
				if ((i % 16) == 0)
					w.Write (String.Format ("\n0x{0:x08}: ", i));
				w.Write (String.Format ("{0:X02} ", bytes [i]));
			}
		}

		void DumpAssemblyTable (TextWriter w) {
			var t = module.AssemblyTable;
			w.WriteLine ("Assembly Table");
			for (int rowIndex = 1; rowIndex <= t.RowCount; rowIndex ++) {
				var r = t.records [rowIndex - 1];
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

		void DumpAssemblyRefTable (TextWriter w) {
			var t = module.AssemblyRef;
			w.WriteLine ("AssemblyRef Table");
			for (int rowIndex = 1; rowIndex <= t.RowCount; rowIndex ++) {
				var r = t.records [rowIndex - 1];
				w.WriteLine (String.Format ("{0}: Version={1}.{2}.{3}.{4}", rowIndex, r.MajorVersion, r.MinorVersion, r.BuildNumber, r.RevisionNumber));
				w.WriteLine (String.Format ("\tName={0}", module.GetString (r.Name)));
				w.WriteLine (String.Format ("\tFlags=0x{0:x08}", r.Flags));
				var blob = module.GetBlob (r.PublicKeyOrToken);
				if (blob.Length == 0) {
					w.WriteLine ("\tZero sized public key");
				} else {
					w.Write ("\tPublic Key:");
					byte[] bytes = blob.ReadBytes (blob.Length);
					HexDump (w, bytes, bytes.Length);
					w.WriteLine ();
				}
				w.WriteLine ();
			}
		}

		void DumpModuleRefTable (TextWriter w) {
			var t = module.ModuleRef;
			w.WriteLine ("ModuleRef Table (1.." + t.RowCount + ")");
			for (int rowIndex = 1; rowIndex <= t.RowCount; rowIndex ++) {
				var r = t.records [rowIndex - 1];
				w.WriteLine (String.Format ("{0}: {1}", rowIndex, module.GetString (r)));
			}
		}

		string StringifyToken (int token) {
			int table = token >> 24;
			return "" + (MetadataTableIndex)table + " " + (token & 0xffffff) + "";
		}

		void DumpEncLogTable (TextWriter w) {
			var t = module.EncLog;
			w.WriteLine ("EncLog Table (1.." + t.RowCount + ")");
			for (int rowIndex = 1; rowIndex <= t.RowCount; rowIndex ++) {
				var r = t.records [rowIndex - 1];
				w.WriteLine (String.Format ("{0}: {1} {2:x} [{3}]", rowIndex, r.FuncCode, r.Token, StringifyToken (r.Token)));
			}
		}

		void DumpEncMapTable (TextWriter w) {
			var t = module.EncMap;
			w.WriteLine ("EncMap Table (1.." + t.RowCount + ")");
			for (int rowIndex = 1; rowIndex <= t.RowCount; rowIndex ++) {
				var r = t.records [rowIndex - 1];
				w.WriteLine (String.Format ("{0}: {1:x} [{2}]", rowIndex, r.Token, StringifyToken (r.Token)));
			}
		}

		void DumpModuleTable (TextWriter w) {
			var t = module.ModuleTable;
			w.WriteLine ("Module Table (1.." + t.RowCount + ")");
			for (int rowIndex = 1; rowIndex <= t.RowCount; rowIndex ++) {
				var r = t.records [rowIndex - 1];
				string encid = r.EncId > 0 ? module.GetGuid (r.EncId).ToString () : "none";
				string encbaseid = r.EncBaseId > 0 ? module.GetGuid (r.EncBaseId).ToString () : "none";
				w.WriteLine (String.Format ("{0}: {1}({2}) mvid={3} encid={4} encbaseid={5}", rowIndex, module.GetString (r.Name), r.Generation, module.GetGuid (r.Mvid), encid, encbaseid));
			}
		}
	}
}
