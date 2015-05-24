package org.xdty.authenticator.security;

import android.content.Context;

import org.xdty.authenticator.androidlockpattern.collect.Lists;
import org.xdty.authenticator.androidlockpattern.util.IEncrypter;
import org.xdty.authenticator.androidlockpattern.widget.LockPatternView.Cell;

import java.util.List;

/**
 * Created by ty on 15-5-21.
 */
public class LPEncrypter implements IEncrypter {

    @Override
    public char[] encrypt(Context context, List<Cell> pattern) {
        /*
         * This is a simple example. And it's also worth mentioning that this is
         * a very weak encrypter, just for fun :-)
         */

        StringBuilder result = new StringBuilder();
        for (Cell cell : pattern)
            result.append(Integer.toString(cell.getId() + 1)).append('-');

        return result.substring(0, result.length() - 1).toCharArray();
    }// encrypt()

    @Override
    public List<Cell> decrypt(Context context, char[] encryptedPattern) {
        List<Cell> result = Lists.newArrayList();
        String[] ids = new String(encryptedPattern).split("[^0-9]");
        for (String id : ids)
            result.add(Cell.of(Integer.parseInt(id) - 1));

        return result;
    }// decrypt()
}
