import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_MosaicLantern {

    public void runMosaicLantern() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_MosaicLanternSource()).loadMosaicLantern();
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

class CWE89_P07_V1_MosaicLanternSource {
    public String loadMosaicLantern() {
        String data;
        data = System.getenv("MOSAIC_LANTERN_FILTER");
        return data;
    }
}
