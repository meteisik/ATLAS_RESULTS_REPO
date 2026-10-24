import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_JadeSundial {
    private static int privateFive = 5;

    public void runJadeSundial() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("JADE_SUNDIAL_FILTER");
        } else {
            data = null;
        }
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
