import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_IvoryKestrel {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryKestrel() throws SQLException {
        String dataCopy;
        {
            String data;
            if (IO.STATIC_FINAL_TRUE) {
                data = System.getenv("IVORY_KESTREL_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection ivoryKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryKestrel");
            Statement ivoryKestrelStatement = null;
            ResultSet ivoryKestrelRows = null;
            try {
                ivoryKestrelStatement = ivoryKestrelConnection.createStatement();
                ivoryKestrelRows = ivoryKestrelStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(ivoryKestrelRows.getRow());
            } finally {
                if (ivoryKestrelRows != null) {
                    ivoryKestrelRows.close();
                }
                if (ivoryKestrelStatement != null) {
                    ivoryKestrelStatement.close();
                }
                ivoryKestrelConnection.close();
            }
        }
    }
}
