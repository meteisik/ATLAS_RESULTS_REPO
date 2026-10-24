import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_IvoryLantern {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryLantern() throws SQLException {
        String dataCopy;
        {
            String data;
            if (IO.staticTrue) {
                data = System.getenv("IVORY_LANTERN_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection ivoryLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryLantern");
            Statement ivoryLanternStatement = null;
            ResultSet ivoryLanternRows = null;
            try {
                ivoryLanternStatement = ivoryLanternConnection.createStatement();
                ivoryLanternRows = ivoryLanternStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(ivoryLanternRows.getRow());
            } finally {
                if (ivoryLanternRows != null) {
                    ivoryLanternRows.close();
                }
                if (ivoryLanternStatement != null) {
                    ivoryLanternStatement.close();
                }
                ivoryLanternConnection.close();
            }
        }
    }
}
