import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_MosaicHelixSafe {

    public void runMosaicHelix() throws SQLException {
        String dataCopy;
        {
            String data;
            data = null;
            for (int j = 0; j < 1; j++) {
                data = "foo";
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection mosaicHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHelix");
            Statement mosaicHelixStatement = null;
            ResultSet mosaicHelixRows = null;
            try {
                mosaicHelixStatement = mosaicHelixConnection.createStatement();
                mosaicHelixRows = mosaicHelixStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(mosaicHelixRows.getRow());
            } finally {
                if (mosaicHelixRows != null) {
                    mosaicHelixRows.close();
                }
                if (mosaicHelixStatement != null) {
                    mosaicHelixStatement.close();
                }
                mosaicHelixConnection.close();
            }
        }
    }
}
