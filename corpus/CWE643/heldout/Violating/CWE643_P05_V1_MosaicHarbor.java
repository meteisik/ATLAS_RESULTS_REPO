import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_MosaicHarbor {

    private String mosaicHarborData;

    private void sinkMosaicHarbor() throws XPathExpressionException {
        String data = mosaicHarborData;
        String mosaicHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            mosaicHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            mosaicHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] mosaicHarborTokens = data.split("||");
            if (mosaicHarborTokens.length < 2) {
                return;
            }
            String mosaicHarborUser = mosaicHarborTokens[0];
            String mosaicHarborPass = mosaicHarborTokens[1];
            XPath mosaicHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource mosaicHarborXml = new InputSource(mosaicHarborXmlFile);
            String mosaicHarborQuery = "//users/user[name/text()='" + mosaicHarborUser
                    + "' and pass/text()='" + mosaicHarborPass + "']" + "/secret/text()";
            String mosaicHarborSecret = (String) mosaicHarborXPath.evaluate(mosaicHarborQuery, mosaicHarborXml, XPathConstants.STRING);
            System.out.println(mosaicHarborSecret);
        }
    }

    public void runMosaicHarbor() throws XPathExpressionException {
        String data;
        data = System.getenv("MOSAIC_HARBOR_ADD");
        mosaicHarborData = data;
        sinkMosaicHarbor();
    }
}
