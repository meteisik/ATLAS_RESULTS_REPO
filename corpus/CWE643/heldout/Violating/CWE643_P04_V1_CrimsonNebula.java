import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V1_CrimsonNebula {

    private String sourceCrimsonNebula() {
        String data;
        data = System.getenv("CRIMSON_NEBULA_ADD");
        return data;
    }

    public void runCrimsonNebula() throws XPathExpressionException {
        String data = sourceCrimsonNebula();
        String crimsonNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonNebulaTokens = data.split("||");
            if (crimsonNebulaTokens.length < 2) {
                return;
            }
            String crimsonNebulaUser = crimsonNebulaTokens[0];
            String crimsonNebulaPass = crimsonNebulaTokens[1];
            XPath crimsonNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonNebulaXml = new InputSource(crimsonNebulaXmlFile);
            String crimsonNebulaQuery = "//users/user[name/text()='" + crimsonNebulaUser
                    + "' and pass/text()='" + crimsonNebulaPass + "']" + "/secret/text()";
            String crimsonNebulaSecret = (String) crimsonNebulaXPath.evaluate(crimsonNebulaQuery, crimsonNebulaXml, XPathConstants.STRING);
            System.out.println(crimsonNebulaSecret);
        }
    }
}
