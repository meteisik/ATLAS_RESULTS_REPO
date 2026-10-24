import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V1_ArcticOrbitSafe {

    public void runArcticOrbit() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String arcticOrbitXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                arcticOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                arcticOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] arcticOrbitTokens = data.split("||");
                if (arcticOrbitTokens.length < 2) {
                    return;
                }
                String arcticOrbitUser = arcticOrbitTokens[0];
                String arcticOrbitPass = arcticOrbitTokens[1];
                XPath arcticOrbitXPath = XPathFactory.newInstance().newXPath();
                InputSource arcticOrbitXml = new InputSource(arcticOrbitXmlFile);
                String arcticOrbitQuery = "//users/user[name/text()='" + arcticOrbitUser
                        + "' and pass/text()='" + arcticOrbitPass + "']" + "/secret/text()";
                String arcticOrbitSecret = (String) arcticOrbitXPath.evaluate(arcticOrbitQuery, arcticOrbitXml, XPathConstants.STRING);
                System.out.println(arcticOrbitSecret);
            }
        }
    }
}
