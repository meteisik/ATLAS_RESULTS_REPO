import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_LunarNebula {

    private String lunarNebulaData;

    private void sinkLunarNebula() throws XPathExpressionException {
        String data = lunarNebulaData;
        String lunarNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            lunarNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            lunarNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] lunarNebulaTokens = data.split("||");
            if (lunarNebulaTokens.length < 2) {
                return;
            }
            String lunarNebulaUser = lunarNebulaTokens[0];
            String lunarNebulaPass = lunarNebulaTokens[1];
            XPath lunarNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource lunarNebulaXml = new InputSource(lunarNebulaXmlFile);
            String lunarNebulaQuery = "//users/user[name/text()='" + lunarNebulaUser
                    + "' and pass/text()='" + lunarNebulaPass + "']" + "/secret/text()";
            String lunarNebulaSecret = (String) lunarNebulaXPath.evaluate(lunarNebulaQuery, lunarNebulaXml, XPathConstants.STRING);
            System.out.println(lunarNebulaSecret);
        }
    }

    public void runLunarNebula() throws XPathExpressionException {
        String data;
        data = System.getenv("LUNAR_NEBULA_ADD");
        lunarNebulaData = data;
        sinkLunarNebula();
    }
}
