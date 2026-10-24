import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_GoldenCipher {

    public void runGoldenCipher() throws SQLException {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_CIPHER_FILTER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection goldenCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCipher");
            Statement goldenCipherStatement = null;
            ResultSet goldenCipherRows = null;
            try {
                goldenCipherStatement = goldenCipherConnection.createStatement();
                goldenCipherRows = goldenCipherStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(goldenCipherRows.getRow());
            } finally {
                if (goldenCipherRows != null) {
                    goldenCipherRows.close();
                }
                if (goldenCipherStatement != null) {
                    goldenCipherStatement.close();
                }
                goldenCipherConnection.close();
            }
        }
    }
}
