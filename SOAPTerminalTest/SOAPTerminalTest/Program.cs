using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Net;
using System.IO;

namespace SOAPTerminalTest
{
     class Program
     {
          private static WSDL _wsdl = null;
          private static string _endpoint = null;
          static void Main(string[] args)
          {
               _endpoint = args[0];
               Console.WriteLine("Fetching th WSDL for service: " + _endpoint);
               HttpWebRequest req = (HttpWebRequest)WebRequest.Create(_endpoint + "?WSDL");
               XmlDocument wsdlDoc = new XmlDocument();
               using (WebResponse resp = req.GetResponse())
               using (Stream respStream = resp.GetResponseStream())
                    wsdlDoc.Load(respStream);

               _wsdl = new WSDL(wsdlDoc);
               Console.WriteLine("Fetched and loaded the web service description.");

               foreach (SoapService service in _wsdl.Services)
                    FuzzService(service);
          }

          static void FuzzSoapPort(SoapBinding binding)
          {
               SoapPortType portType = _wsdl.PortTypes.Single(pt => pt.Name == binding.Type.Split(':')[1]);

               foreach (SoapBindingOperation op in binding.Operations)
               {
                    Console.WriteLine("Fuzzing operation: "+op.Name);
                    SoapOperation po = portType.Operations.Single(p => p.Name == op.Name);
                    SoapMessage input = _wsdl.Messages.Single(m => m.Name == po.Input.Split(':')[1]);

                    XNamespace soapNS = "http://schemas.xmlsoap.org/soap/envelope/";
                    XNamespace xmlNS = op.SoapAction.Replace(op.Name, string.Empty);
                    XElement soapBody = new XElement(soapNS + "Body");
                    XElement soapOperation = new XElement(xmlNS + op.Name);

                    soapBody.Add(soapOperation);

                    List<Guid> paramList = new List<Guid>();
                    SoapType type = _wsdl.Types.Single(t => t.Name == input.Parts[0].Element.Split(':')[1]);
                    foreach (SoapTypeParameter param in type.Parameters)
                    {
                         XElement soapParam = new XElement(xmlNS + param.Name);
                         if (param.Type.EndsWith("string"))
                         {
                              Guid guid = Guid.NewGuid();
                              paramList.Add(guid);
                              soapParam.SetValue(guid.ToString());
                         }
                         soapOperation.Add(soapParam);
                    }

                    XDocument soapDoc = new XDocument(new XDeclaration("1.0", "ascii", "true"), new XElement(soapNS + "Envelope", new XAttribute(XNamespace.Xmlns + "soap", soapNS), new XAttribute("xmlns", xmlNS), soapBody));

                    int k = 0;
                    foreach (Guid parm in paramList)
                    {
                         string testSoap = soapDoc.ToString().Replace(parm.ToString(), "fd'sa");
                         byte[] data = System.Text.Encoding.ASCII.GetBytes(testSoap);
                         HttpWebRequest req = (HttpWebRequest)WebRequest.Create(_endpoint);

                         req.Headers["SOAPAction"] = op.SoapAction;
                         req.Method = "POST";
                         req.ContentType = "text/xml";
                         req.ContentLength = data.Length;

                         using (Stream stream = req.GetRequestStream())
                              stream.Write(data, 0, data.Length);

                         string resp = string.Empty;
                         try
                         {
                              using (StreamReader rdr = new StreamReader(req.GetResponse().GetResponseStream()))
                                   resp = rdr.ReadToEnd();
                         }
                         catch (WebException ex)
                         {
                              using (StreamReader rdr = new StreamReader(ex.Response.GetResponseStream()))
                                   resp = rdr.ReadToEnd();

                              if (resp.Contains("syntax error"))
                                   Console.WriteLine("Possible SQL injection vector in parameter: ");
                              Console.Write(type.Parameters[k].Name);
                         }
                         k++;
                    }
               }
          }

          static void FuzzService(SoapService service)
          {
               Console.WriteLine("Fuzzing service: " + service.Name);

               foreach (SoapPort port in service.Ports)
               {
                    Console.WriteLine("Fuzzing "+port.ElementType.Split(':')[0]+"port: "+port.Name);
                    SoapBinding binding = _wsdl.Bindings.Single(b => b.Name == port.Binding.Split(':')[1]);
                    if (binding.IsHTTP)
                         FuzzHttpPort(binding);
                    else
                         FuzzSoapPort(binding);
               }
          }

          static void FuzzHttpGetPort(SoapBinding binding)
          {
               SoapPortType portType = _wsdl.PortTypes.Single(pt => pt.Name == binding.Type.Split(':')[1]);
               foreach (SoapBindingOperation op in binding.Operations)
               {
                    Console.WriteLine("Fuzzing operation: "+op.Name);
                    string url = _endpoint + op.Location;
                    SoapOperation po = portType.Operations.Single(p => p.Name == op.Name);
                    SoapMessage input = _wsdl.Messages.Single(m => m.Name == po.Input.Split(':')[1]);
                    Dictionary<string, string> parameters = new Dictionary<string, string>();

                    foreach (SoapMessagePart part in input.Parts)
                         parameters.Add(part.Name, part.Type);

                    bool first = true;
                    List<Guid> guidList = new List<Guid>();
                    foreach (var param in parameters)
                    {
                         if (param.Value.EndsWith("string"))
                         {
                              Guid guid = Guid.NewGuid();
                              guidList.Add(guid);
                              url += (first ? "?" : "&") + param.Key + "=" + guid.ToString();
                         }
                         first = false;
                    }
                    Console.WriteLine("Fuzzing full url: "+url);
                    int k = 0;
                    foreach (Guid guid in guidList)
                    {
                         string testUrl = url.Replace(guid.ToString(), "fd'sa");
                         HttpWebRequest req = (HttpWebRequest)WebRequest.Create(testUrl);
                         string resp = string.Empty;
                         try
                         {
                              using (StreamReader rdr = new StreamReader(req.GetResponse().GetResponseStream()))
                                   resp = rdr.ReadToEnd();
                         }
                         catch (WebException ex)
                         {
                              using (StreamReader rdr = new StreamReader(ex.Response.GetResponseStream()))
                                   resp = rdr.ReadToEnd();
                         
                              if (resp.Contains("syntax error"))
                                   Console.WriteLine("Possible SQL injection vector in parameter: "+input.Parts[k].Name);
                         }
                         k++;
                    }
               }
          }

          static void FuzzHttpPostPort(SoapBinding binding)
          {
               SoapPortType portType = _wsdl.PortTypes.Single(pt => pt.Name == binding.Type.Split(':')[1]);
               foreach (SoapBindingOperation op in binding.Operations)
               {
                    Console.WriteLine("Fuzzing Operation: "+op.Name);
                    string url = _endpoint + op.Location;
                    SoapOperation po = portType.Operations.Single(p => p.Name == op.Name);
                    SoapMessage input = _wsdl.Messages.Single(m => m.Name == po.Input.Split(':')[1]);
                    Dictionary<string, string> parameters = new Dictionary<string, string>();

                    foreach (SoapMessagePart part in input.Parts)
                         parameters.Add(part.Name, part.Type);

                    string postParams = string.Empty;
                    bool first = true;
                    List<Guid> guids = new List<Guid>();
                    foreach (var param in parameters)
                    {
                         if (param.Value.EndsWith("string"))
                         {
                              Guid guid = Guid.NewGuid();
                              postParams += (first ? "" : "&") + param.Key + "=" + guid.ToString();
                              guids.Add(guid);
                         }
                         if (first)
                         {
                              first = false;
                         }
                    }

                    int k = 0;
                    foreach (Guid guid in guids)
                    {
                         string testParams = postParams.Replace(guid.ToString(), "fd'sa");
                         byte[] data = System.Text.Encoding.ASCII.GetBytes(testParams);

                         HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                         req.Method = "POST";
                         req.ContentType = "application/x-www-form-urlencoded";
                         req.ContentLength = data.Length;
                         req.GetRequestStream().Write(data, 0, data.Length);

                         string resp = string.Empty;
                         try
                         {
                              using (StreamReader rdr = new StreamReader(req.GetResponse().GetResponseStream()))
                                   resp = rdr.ReadToEnd();
                         }
                         catch (WebException ex)
                         {
                              using (StreamReader rdr = new StreamReader(ex.Response.GetResponseStream()))
                                   resp = rdr.ReadToEnd();

                              if (resp.Contains("syntax error"))
                                   Console.WriteLine("Possible SQL injection vector in parameter: "+input.Parts[k].Name);
                         }
                         k++;
                    }
               }
          }

          static void FuzzHttpPort(SoapBinding binding)
          {
               if (binding.Verb == "GET")
                    FuzzHttpGetPort(binding);
               else if (binding.Verb == "POST")
                    FuzzHttpPostPort(binding);
               else
                    throw new Exception("Don't know Verb: " + binding.Verb);
          }

          public class SoapType
          {
               public SoapType(XmlNode type)
               {
                    this.Name = type.Attributes["name"].Value;
                    this.Parameters = new List<SoapTypeParameter>();
                    if (type.HasChildNodes && type.FirstChild.HasChildNodes)
                    {
                         foreach (XmlNode node in type.FirstChild.ChildNodes)
                              this.Parameters.Add(new SoapTypeParameter(node));
                    }
               }
               public string Name { get; set; }
               public List<SoapTypeParameter> Parameters { get; set; }
          }

          public class SoapTypeParameter
          {
               public SoapTypeParameter(XmlNode node)
               {
                    if (node.Attributes["MaxOccurs"].Value == "unbounded")
                         this.MaximumOccurrence = int.MaxValue;
                    else
                         this.MaximumOccurrence = int.Parse(node.Attributes["minOccurs"].Value);
                    this.Name = node.Attributes["name"].Value;
                    this.Type = node.Attributes["type"].Value;
               }
               public int MinimunOccurrence { get; set; }
               public int MaximumOccurrence { get; set; }
               public string Name { get; set; }
               public string Type { get; set; }
          }

          public class SoapMessage
          {
               public SoapMessage(XmlNode node)
               {
                    this.Name = node.Attributes["name"].Value;
                    this.Parts = new List<SoapMessagePart>();
                    if (node.HasChildNodes)
                    {
                         foreach (XmlNode part in node.ChildNodes)
                              this.Parts.Add(new SoapMessagePart(part));
                    }
               }
               public string Name { get; set; }
               public List<SoapMessagePart> Parts { get; set; }
          }

          public class SoapMessagePart
          {
               public SoapMessagePart(XmlNode part)
               {
                    this.Name = part.Attributes["name"].Value;
                    if (part.Attributes["element"] != null)
                         this.Element = part.Attributes["element"].Value;
                    else if (part.Attributes["type"].Value != null)
                         this.Type = part.Attributes["type"].Value;
                    else
                         throw new ArgumentException("Neither element nor type is set.", "part");
               }
               public string Name { get; set; }
               public string Element { get; set; }
               public string Type { get; set; }

          }

          public class SoapOperation
          {
               public SoapOperation(XmlNode op)
               {
                    this.Name = op.Attributes["name"].Value;
                    foreach (XmlNode message in op.ChildNodes)
                    {
                         if (message.Name.EndsWith("input"))
                              this.Input = message.Attributes["message"].Value;
                         else if (message.Name.EndsWith("output"))
                              this.Output = message.Attributes["message"].Value;
                    }
               }
               public string Name { get; set; }
               public string Input { get; set; }
               public string Output { get; set; }
          }

          public class SoapPortType
          {
               public SoapPortType(XmlNode node)
               {
                    this.Name = node.Attributes["name"].Value;
                    this.Operations = new List<SoapOperation>();
                    foreach (XmlNode op in node.ChildNodes)
                         this.Operations.Add(new SoapOperation(op));
               }
               public string Name { get; set; }
               public List<SoapOperation> Operations { get; set; }
          }

          public class SoapBindingOperation
          {
               public SoapBindingOperation(XmlNode op)
               {
                    this.Name = op.Attributes["name"].Value;
                    foreach (XmlNode node in op.ChildNodes)
                    {
                         if (node.Name == "http:operation")
                              this.Location = node.Attributes["location"].Value;
                         else if (node.Name == "soap:operation" || node.Name == "soap12:operation")
                              this.SoapAction = node.Attributes["soapAction"].Value;
                    }
               }
               public string Name { get; set; }
               public string Location { get; set; }
               public string SoapAction { get; set; }
          }

          public class SoapBinding
          {
               public SoapBinding(XmlNode node)
               {
                    this.Name = node.Attributes["name"].Value;
                    this.Type = node.Attributes["type"].Value;
                    this.IsHTTP = false;
                    this.Operations = new List<SoapBindingOperation>();
                    foreach (XmlNode op in node.ChildNodes)
                    {
                         if (op.Name.EndsWith("operation"))
                         {
                              this.Operations.Add(new SoapBindingOperation(op));
                         }
                         else if (op.Name == "http:binding")
                         {
                              this.Verb = op.Attributes["verb"].Value;
                              this.IsHTTP = true;
                         }
                    }
               }
               public string Name { get; set; }
               public List<SoapBindingOperation> Operations { get; set; }
               public bool IsHTTP { get; set; }
               public string Verb { get; set; }
               public string Type { get; set; }

          }

          public class SoapPort
          {
               public SoapPort(XmlNode port)
               {
                    this.Name = port.Attributes["name"].Value;
                    this.Binding = port.Attributes["binding"].Value;
                    this.ElementType = port.FirstChild.Name;
                    this.Location = port.FirstChild.Attributes["location"].Value;
               }
               public string Name { get; set; }
               public string Binding { get; set; }
               public string ElementType { get; set; }
               public string Location { get; set; }
          }

          public class SoapService
          {
               public SoapService(XmlNode node)
               {
                    this.Name = node.Attributes["name"].Value;
                    this.Ports = new List<SoapPort>();
                    foreach (XmlNode port in node.ChildNodes)
                         this.Ports.Add(new SoapPort(port));
               }
               public string Name { get; set; }
               public List<SoapPort> Ports { get; set; }
          }

          public class WSDL
          {
               public WSDL(XmlDocument doc)
               {
                    XmlNamespaceManager nsManager = new XmlNamespaceManager(doc.NameTable);
                    nsManager.AddNamespace("wsdl", doc.DocumentElement.NamespaceURI);
                    nsManager.AddNamespace("xs", "http://www.w3.org/2001/XMLSchema");

                    ParseTypes(doc, nsManager);
                    ParseMessages(doc, nsManager);
                    ParsePortTypes(doc, nsManager);
                    ParseBindings(doc, nsManager);
                    ParseServices(doc, nsManager);
               }

               private void ParseTypes(XmlDocument wsdl, XmlNamespaceManager nsManager)
               {
                    this.Types = new List<SoapType>();
                    string xpath = "/wsdl:definitions/wsdl:types/xs:schema/xs:element";
                    XmlNodeList nodes = wsdl.DocumentElement.SelectNodes(xpath, nsManager);
                    foreach (XmlNode type in nodes)
                         this.Types.Add(new SoapType(type));
               }

               private void ParseMessages(XmlDocument wsdl, XmlNamespaceManager nsManager)
               {
                    this.Messages = new List<SoapMessage>();
                    string xpath = "/wsdl:definitions/wsdl:message";
                    XmlNodeList nodes = wsdl.DocumentElement.SelectNodes(xpath, nsManager);
                    foreach (XmlNode node in nodes)
                         this.Messages.Add(new SoapMessage(node));
               }

               private void ParsePortTypes(XmlDocument wsdl, XmlNamespaceManager nsManager)
               {
                    this.PortTypes = new List<SoapPortType>();
                    string xpath = "/wsdl:definitions/wsdl:portType";
                    XmlNodeList nodes = wsdl.DocumentElement.SelectNodes(xpath, nsManager);
                    foreach (XmlNode node in nodes)
                         this.PortTypes.Add(new SoapPortType(node));
               }

               private void ParseBindings(XmlDocument wsdl, XmlNamespaceManager nsManager)
               {
                    this.Bindings = new List<SoapBinding>();
                    string xpath = "/wsdl:definitions/wsdl:binding";
                    XmlNodeList nodes = wsdl.DocumentElement.SelectNodes(xpath, nsManager);
                    foreach (XmlNode node in nodes)
                         this.Bindings.Add(new SoapBinding(node));
               }

               private void ParseServices(XmlDocument wsdl, XmlNamespaceManager nsManager)
               {
                    this.Services = new List<SoapService>();
                    string xpath = "wsdl:definitions/wsdl:service";
                    XmlNodeList nodes = wsdl.DocumentElement.SelectNodes(xpath, nsManager);
                    foreach (XmlNode node in nodes)
                         this.Services.Add(new SoapService(node));
               }

               public List<SoapType> Types { get; set; }
               public List<SoapMessage> Messages { get; set; }
               public List<SoapPortType> PortTypes { get; set; }
               public List<SoapBinding> Bindings { get; set; }
               public List<SoapService> Services { get; set; }
          }

          
     }
}
