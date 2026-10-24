import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_IvoryLotusSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryLotus() throws SQLException {
        String dataCopy;
        {
            String data;
            if (IO.staticReturnsTrue()) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection ivoryLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryLotus");
            Statement ivoryLotusStatement = null;
            ResultSet ivoryLotusRows = null;
            try {
                ivoryLotusStatement = ivoryLotusConnection.createStatement();
                ivoryLotusRows = ivoryLotusStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(ivoryLotusRows.getRow());
            } finally {
                if (ivoryLotusRows != null) {
                    ivoryLotusRows.close();
                }
                if (ivoryLotusStatement != null) {
                    ivoryLotusStatement.close();
                }
                ivoryLotusConnection.close();
            }
        }
    }
}
