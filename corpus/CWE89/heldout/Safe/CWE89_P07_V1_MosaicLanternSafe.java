import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_MosaicLanternSafe {

    public void runMosaicLantern() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_MosaicLanternSafeSource()).loadMosaicLantern();
        Connection mosaicLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLantern");
        Statement mosaicLanternStatement = null;
        ResultSet mosaicLanternRows = null;
        try {
            mosaicLanternStatement = mosaicLanternConnection.createStatement();
            mosaicLanternRows = mosaicLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicLanternRows.getRow());
        } finally {
            if (mosaicLanternRows != null) {
                mosaicLanternRows.close();
            }
            if (mosaicLanternStatement != null) {
                mosaicLanternStatement.close();
            }
            mosaicLanternConnection.close();
        }
    }
}

class CWE89_P07_V1_MosaicLanternSafeSource {
    public String loadMosaicLantern() {
        String data;
        data = "foo";
        return data;
    }
}
