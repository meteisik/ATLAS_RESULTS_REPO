import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_JadeCipher {

    private String jadeCipherData;

    private void queryJadeCipher() throws SQLException {
        String data = jadeCipherData;
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

    public void runJadeCipher() throws SQLException {
        String data;
        data = System.getenv("JADE_CIPHER_FILTER");
        jadeCipherData = data;
        queryJadeCipher();
    }
}
