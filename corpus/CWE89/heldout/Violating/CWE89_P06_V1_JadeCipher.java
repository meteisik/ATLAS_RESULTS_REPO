import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_JadeCipher {

    public void runJadeCipher() throws SQLException {
        String data;
        data = System.getenv("JADE_CIPHER_FILTER");
        (new CWE89_P06_V1_JadeCipherSink()).queryJadeCipher(data);
    }
}

class CWE89_P06_V1_JadeCipherSink {
    public void queryJadeCipher(String data) throws SQLException {
        Connection jadeCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeCipher");
        Statement jadeCipherStatement = null;
        ResultSet jadeCipherRows = null;
        try {
            jadeCipherStatement = jadeCipherConnection.createStatement();
            jadeCipherRows = jadeCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(jadeCipherRows.getRow());
        } finally {
            if (jadeCipherRows != null) {
                jadeCipherRows.close();
            }
            if (jadeCipherStatement != null) {
                jadeCipherStatement.close();
            }
            jadeCipherConnection.close();
        }
    }
}
