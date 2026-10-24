import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_MosaicLantern {

    public void runMosaicLantern() throws SQLException {
        String dataCopy;
        {
            String data;
            if (5 == 5) {
                data = System.getenv("MOSAIC_LANTERN_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
