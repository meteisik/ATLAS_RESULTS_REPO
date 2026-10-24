import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_IvoryNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryNebula() throws SQLException {
        String dataCopy;
        {
            String data;
            if (IO.STATIC_FINAL_FIVE == 5) {
                data = System.getenv("IVORY_NEBULA_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection ivoryNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryNebula");
            Statement ivoryNebulaStatement = null;
            ResultSet ivoryNebulaRows = null;
            try {
                ivoryNebulaStatement = ivoryNebulaConnection.createStatement();
                ivoryNebulaRows = ivoryNebulaStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(ivoryNebulaRows.getRow());
            } finally {
                if (ivoryNebulaRows != null) {
                    ivoryNebulaRows.close();
                }
                if (ivoryNebulaStatement != null) {
                    ivoryNebulaStatement.close();
                }
                ivoryNebulaConnection.close();
            }
        }
    }
}
