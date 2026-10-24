import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ArcticNebulaSafe {

    public static String data;

    public void runArcticNebula() throws XPathExpressionException {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        (new CWE643_P10_V2_ArcticNebulaSafeSink()).sinkArcticNebula();
    }
}

class CWE643_P10_V2_ArcticNebulaSafeSink {

    public void sinkArcticNebula() throws XPathExpressionException {
        String data = CWE643_P10_V2_ArcticNebulaSafe.data;
        String arcticNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticNebulaTokens = data.split("||");
            if (arcticNebulaTokens.length < 2) {
                return;
            }
            String arcticNebulaUser = arcticNebulaTokens[0];
            String arcticNebulaPass = arcticNebulaTokens[1];
            XPath arcticNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticNebulaXml = new InputSource(arcticNebulaXmlFile);
            String arcticNebulaQuery = "//users/user[name/text()='" + arcticNebulaUser
                    + "' and pass/text()='" + arcticNebulaPass + "']" + "/secret/text()";
            String arcticNebulaSecret = (String) arcticNebulaXPath.evaluate(arcticNebulaQuery, arcticNebulaXml, XPathConstants.STRING);
            System.out.println(arcticNebulaSecret);
        }
    }
}
