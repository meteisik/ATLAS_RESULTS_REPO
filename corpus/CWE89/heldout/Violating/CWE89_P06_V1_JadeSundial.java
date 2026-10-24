import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_JadeSundial {

    public void runJadeSundial() throws SQLException {
        String data;
        data = System.getenv("JADE_SUNDIAL_FILTER");
        (new CWE89_P06_V1_JadeSundialSink()).queryJadeSundial(data);
    }
}

class CWE89_P06_V1_JadeSundialSink {
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
