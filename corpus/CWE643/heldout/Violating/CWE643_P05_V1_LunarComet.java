import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_LunarComet {

    private String lunarCometData;

    private void sinkLunarComet() throws XPathExpressionException {
        String data = lunarCometData;
        String lunarCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            lunarCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            lunarCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] lunarCometTokens = data.split("||");
            if (lunarCometTokens.length < 2) {
                return;
            }
            String lunarCometUser = lunarCometTokens[0];
            String lunarCometPass = lunarCometTokens[1];
            XPath lunarCometXPath = XPathFactory.newInstance().newXPath();
            InputSource lunarCometXml = new InputSource(lunarCometXmlFile);
            String lunarCometQuery = "//users/user[name/text()='" + lunarCometUser
                    + "' and pass/text()='" + lunarCometPass + "']" + "/secret/text()";
            String lunarCometSecret = (String) lunarCometXPath.evaluate(lunarCometQuery, lunarCometXml, XPathConstants.STRING);
            System.out.println(lunarCometSecret);
        }
    }

    public void runLunarComet() throws XPathExpressionException {
        String data;
        data = System.getenv("LUNAR_COMET_ADD");
        lunarCometData = data;
        sinkLunarComet();
    }
}
