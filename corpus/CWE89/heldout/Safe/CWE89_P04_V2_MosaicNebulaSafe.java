import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_MosaicNebulaSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String loadMosaicNebula() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void runMosaicNebula() throws SQLException {
        String data = loadMosaicNebula();
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
