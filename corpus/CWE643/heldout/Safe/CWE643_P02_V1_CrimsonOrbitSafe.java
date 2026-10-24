import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V1_CrimsonOrbitSafe {

    public void runCrimsonOrbit() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String crimsonOrbitXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                crimsonOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                crimsonOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] crimsonOrbitTokens = data.split("||");
                if (crimsonOrbitTokens.length < 2) {
                    return;
                }
                String crimsonOrbitUser = crimsonOrbitTokens[0];
                String crimsonOrbitPass = crimsonOrbitTokens[1];
                XPath crimsonOrbitXPath = XPathFactory.newInstance().newXPath();
                InputSource crimsonOrbitXml = new InputSource(crimsonOrbitXmlFile);
                String crimsonOrbitQuery = "//users/user[name/text()='" + crimsonOrbitUser
                        + "' and pass/text()='" + crimsonOrbitPass + "']" + "/secret/text()";
                String crimsonOrbitSecret = (String) crimsonOrbitXPath.evaluate(crimsonOrbitQuery, crimsonOrbitXml, XPathConstants.STRING);
                System.out.println(crimsonOrbitSecret);
            }
        }
    }
}
