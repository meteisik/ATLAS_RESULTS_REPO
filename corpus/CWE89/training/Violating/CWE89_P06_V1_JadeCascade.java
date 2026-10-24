import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_JadeCascade {

    public void runJadeCascade() throws SQLException {
        String data;
        data = System.getenv("JADE_CASCADE_FILTER");
        (new CWE89_P06_V1_JadeCascadeSink()).queryJadeCascade(data);
    }
}

class CWE89_P06_V1_JadeCascadeSink {
    public void queryJadeCascade(String data) throws SQLException {
        Connection jadeCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeCascade");
        Statement jadeCascadeStatement = null;
        ResultSet jadeCascadeRows = null;
        try {
            jadeCascadeStatement = jadeCascadeConnection.createStatement();
            jadeCascadeRows = jadeCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(jadeCascadeRows.getRow());
        } finally {
            if (jadeCascadeRows != null) {
                jadeCascadeRows.close();
            }
            if (jadeCascadeStatement != null) {
                jadeCascadeStatement.close();
            }
            jadeCascadeConnection.close();
        }
    }
}
