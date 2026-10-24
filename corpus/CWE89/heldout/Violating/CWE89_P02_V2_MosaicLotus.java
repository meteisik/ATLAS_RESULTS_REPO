import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_MosaicLotus {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runMosaicLotus() throws SQLException {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_TRUE) {
                data = System.getenv("MOSAIC_LOTUS_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection mosaicLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLotus");
            Statement mosaicLotusStatement = null;
            ResultSet mosaicLotusRows = null;
            try {
                mosaicLotusStatement = mosaicLotusConnection.createStatement();
                mosaicLotusRows = mosaicLotusStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(mosaicLotusRows.getRow());
            } finally {
                if (mosaicLotusRows != null) {
                    mosaicLotusRows.close();
                }
                if (mosaicLotusStatement != null) {
                    mosaicLotusStatement.close();
                }
                mosaicLotusConnection.close();
            }
        }
    }
}
