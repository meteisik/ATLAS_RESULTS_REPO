import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_JadeCascadeSafe {

    public void runJadeCascade() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_JadeCascadeSafeSink()).queryJadeCascade(data);
    }
}

class CWE89_P06_V1_JadeCascadeSafeSink {
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
