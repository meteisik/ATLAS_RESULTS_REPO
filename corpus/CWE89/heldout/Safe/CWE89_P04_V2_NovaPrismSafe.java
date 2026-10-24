import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_NovaPrismSafe {

    private String loadNovaPrism() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        return data;
    }

    public void runNovaPrism() throws SQLException {
        String data = loadNovaPrism();
        Connection novaPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaPrism");
        Statement novaPrismStatement = null;
        ResultSet novaPrismRows = null;
        try {
            novaPrismStatement = novaPrismConnection.createStatement();
            novaPrismRows = novaPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaPrismRows.getRow());
        } finally {
            if (novaPrismRows != null) {
                novaPrismRows.close();
            }
            if (novaPrismStatement != null) {
                novaPrismStatement.close();
            }
            novaPrismConnection.close();
        }
    }
}
