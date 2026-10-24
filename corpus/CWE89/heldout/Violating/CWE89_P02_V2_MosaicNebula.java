import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_MosaicNebula {
    private static boolean privateTrue = true;

    public void runMosaicNebula() throws SQLException {
        String dataCopy;
        {
            String data;
            if (privateTrue) {
                data = System.getenv("MOSAIC_NEBULA_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection mosaicNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicNebula");
            Statement mosaicNebulaStatement = null;
            ResultSet mosaicNebulaRows = null;
            try {
                mosaicNebulaStatement = mosaicNebulaConnection.createStatement();
                mosaicNebulaRows = mosaicNebulaStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(mosaicNebulaRows.getRow());
            } finally {
                if (mosaicNebulaRows != null) {
                    mosaicNebulaRows.close();
                }
                if (mosaicNebulaStatement != null) {
                    mosaicNebulaStatement.close();
                }
                mosaicNebulaConnection.close();
            }
        }
    }
}
