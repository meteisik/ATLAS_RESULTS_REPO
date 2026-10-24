import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_JadeSundialSafe {

    private String jadeSundialData;

    private void queryJadeSundial() throws SQLException {
        String data = jadeSundialData;
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

    public void runJadeSundial() throws SQLException {
        String data;
        data = "foo";
        jadeSundialData = data;
        queryJadeSundial();
    }
}
