import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_JadeCipherSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private void queryJadeCipher(String data) throws SQLException {
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
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        queryJadeCipher(data);
    }
}
