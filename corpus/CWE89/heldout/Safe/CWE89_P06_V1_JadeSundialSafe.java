import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_JadeSundialSafe {

    public void runJadeSundial() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_JadeSundialSafeSink()).queryJadeSundial(data);
    }
}

class CWE89_P06_V1_JadeSundialSafeSink {
    public void queryJadeSundial(String data) throws SQLException {
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
