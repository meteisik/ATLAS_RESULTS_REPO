import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_MosaicNebula {

    public void runMosaicNebula() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_MosaicNebulaSource()).loadMosaicNebula();
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

class CWE89_P07_V1_MosaicNebulaSource {
    public String loadMosaicNebula() {
        String data;
        data = System.getenv("MOSAIC_NEBULA_FILTER");
        return data;
    }
}
