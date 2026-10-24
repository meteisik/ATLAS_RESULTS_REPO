import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_JadeCascade {

    public void runJadeCascade() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("JADE_CASCADE_FILTER");
            break;
        default:
            data = null;
            break;
        }
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
