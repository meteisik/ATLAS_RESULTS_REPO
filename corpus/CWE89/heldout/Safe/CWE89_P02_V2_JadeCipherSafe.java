import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_JadeCipherSafe {

    public void runJadeCipher() throws SQLException {
        String dataCopy;
        {
            String data;
            if (true) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
