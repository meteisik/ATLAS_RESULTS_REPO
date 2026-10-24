import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_JadeSundial {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runJadeSundial() throws SQLException {
        String dataCopy;
        {
            String data;
            if (IO.STATIC_FINAL_TRUE) {
                data = System.getenv("JADE_SUNDIAL_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection jadeSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeSundial");
            Statement jadeSundialStatement = null;
            ResultSet jadeSundialRows = null;
            try {
                jadeSundialStatement = jadeSundialConnection.createStatement();
                jadeSundialRows = jadeSundialStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(jadeSundialRows.getRow());
            } finally {
                if (jadeSundialRows != null) {
                    jadeSundialRows.close();
                }
                if (jadeSundialStatement != null) {
                    jadeSundialStatement.close();
                }
                jadeSundialConnection.close();
            }
        }
    }
}
