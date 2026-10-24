import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_JadeMantisSafe {

    private String loadJadeMantis() {
        String data;
        data = "foo";
        return data;
    }

    public void runJadeMantis() throws SQLException {
        String data = loadJadeMantis();
        Connection jadeMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeMantis");
        Statement jadeMantisStatement = null;
        ResultSet jadeMantisRows = null;
        try {
            jadeMantisStatement = jadeMantisConnection.createStatement();
            jadeMantisRows = jadeMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(jadeMantisRows.getRow());
        } finally {
            if (jadeMantisRows != null) {
                jadeMantisRows.close();
            }
            if (jadeMantisStatement != null) {
                jadeMantisStatement.close();
            }
            jadeMantisConnection.close();
        }
    }
}
