import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_MosaicKestrelSafe {

    public void runMosaicKestrel() throws SQLException {
        String dataCopy;
        {
            String data;
            if (true) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection mosaicKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicKestrel");
            Statement mosaicKestrelStatement = null;
            ResultSet mosaicKestrelRows = null;
            try {
                mosaicKestrelStatement = mosaicKestrelConnection.createStatement();
                mosaicKestrelRows = mosaicKestrelStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(mosaicKestrelRows.getRow());
            } finally {
                if (mosaicKestrelRows != null) {
                    mosaicKestrelRows.close();
                }
                if (mosaicKestrelStatement != null) {
                    mosaicKestrelStatement.close();
                }
                mosaicKestrelConnection.close();
            }
        }
    }
}
